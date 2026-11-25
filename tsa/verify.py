"""Contract for the timestamp-authority response verifier.

The eight public functions below implement the verification contract defined
by the tests in this repository; their signatures must stay unchanged.

Response JSON schema::

    {
        "algorithm": "sha256" | "sha384" | "sha512",
        "digest": "<lowercase hex digest of the original document>",
        "serial": <positive integer>,
        "time": "YYYY-MM-DDTHH:MM:SSZ",
        "issuer": "<exact issuer name>",
        "signature": "<lowercase hex HMAC-SHA256>"
    }

The signature is HMAC-SHA256 over the UTF-8 encoding of the canonical JSON
object containing exactly the keys algorithm, digest, issuer, serial and
time, serialized with sort_keys=True, separators=(",", ":") and
ensure_ascii=False.  The time value in that canonical object is formatted as
YYYY-MM-DDTHH:MM:SSZ in UTC.

A serial ledger is a JSON file with this shape::

    {"max_serial": 0, "used": []}

The special reason string "serial_reuse" is used when a serial is not
strictly greater than max_serial or is already present in used.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Algorithms declared by the response schema.  The verifier never falls back
# to a default algorithm and never accepts anything outside this whitelist.
_SUPPORTED_ALGORITHMS = frozenset({"sha256", "sha384", "sha512"})


def _is_positive_int(value):
    """Return True for genuine positive ints (bool is not accepted as int)."""
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _load_ledger(store):
    """Read a serial ledger, treating a missing file as the empty ledger."""
    path = Path(store)
    if not path.exists():
        return {"max_serial": 0, "used": []}
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    max_serial = data.get("max_serial", 0)
    used = list(data.get("used", []))
    return {"max_serial": max_serial, "used": used}


def _write_ledger_atomic(store, max_serial, used):
    """Atomically replace the ledger file so a fresh process observes it."""
    path = Path(store)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {"max_serial": max_serial, "used": list(used)},
        sort_keys=True,
        separators=(",", ":"),
    )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def _as_utc(value):
    """Normalize a naive/aware datetime to an aware UTC datetime."""
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _canonical_time(value):
    """Format the signed time as YYYY-MM-DDTHH:MM:SSZ in UTC."""
    moment = _as_utc(value) if isinstance(value, datetime) else None
    if moment is not None:
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


def parse_response(raw):
    """Parse raw response bytes and normalize every field for verification.

    The returned mapping must contain algorithm, digest, serial, time, issuer
    and signature.  time must be a timezone-aware UTC datetime; digest and
    signature must be lowercase hex strings.
    """
    if isinstance(raw, (bytes, bytearray)):
        text = bytes(raw).decode("utf-8")
    else:
        text = str(raw)

    data = json.loads(text)

    time_value = data["time"]
    if isinstance(time_value, datetime):
        moment = _as_utc(time_value)
    else:
        moment = datetime.fromisoformat(
            str(time_value).replace("Z", "+00:00")
        )
        moment = _as_utc(moment)

    return {
        "algorithm": str(data["algorithm"]).lower(),
        "digest": str(data["digest"]).lower(),
        "serial": data["serial"],
        "time": moment,
        "issuer": data["issuer"],
        "signature": str(data["signature"]).lower(),
    }


def check_imprint(response, document):
    """Return True only when the document digest matches the declared digest.

    The digest algorithm must be selected from response["algorithm"], never
    from a default.  Unsupported algorithms and malformed values are rejected.
    """
    try:
        algorithm = str(response["algorithm"]).lower()
        # DEFECT-2 FIX: use the algorithm declared by the response, and only
        # accept the schema's algorithm whitelist (no silent default).
        if algorithm not in _SUPPORTED_ALGORITHMS:
            return False
        expected = hashlib.new(algorithm, document).hexdigest()
        supplied = response["digest"]
        # DEFECT-1 FIX: compare the complete digest, never just its length.
        return isinstance(supplied, str) and hmac.compare_digest(
            expected, supplied.lower()
        )
    except (KeyError, TypeError, ValueError):
        return False


def check_serial(response, store):
    """Return True only when the serial is strictly greater than the ledger max.

    store is a path to a JSON ledger.  A missing ledger is empty
    (max_serial 0, used []).  Serials already present in used are invalid.
    """
    try:
        serial = response["serial"]
        # DEFECT-3 FIX: positivity alone is not enough; require a genuine
        # positive integer that is strictly beyond the ledger high-water mark
        # and has never been recorded in used.
        if not _is_positive_int(serial):
            return False
        ledger = _load_ledger(store)
        if serial <= ledger["max_serial"]:
            return False
        if serial in ledger["used"]:
            return False
        return True
    except (KeyError, TypeError, ValueError, OSError):
        return False


def check_time(response, now, window):
    """Return True only for a positive window and an inclusive time window.

    The accepted interval is [now - window, now + window].  A zero or negative
    window is invalid.  A timestamp beyond either boundary is rejected.
    """
    try:
        moment = _as_utc(response["time"])
        current = _as_utc(now)
        if moment is None or current is None:
            return False
        if not isinstance(window, timedelta):
            return False
        # DEFECT-6 FIX: a zero-length (or negative) window validates nothing
        # and must be rejected outright.
        if window <= timedelta(0):
            return False
        # DEFECT-5 FIX: enforce both sides of the inclusive interval
        # [now - window, now + window]; future timestamps are no longer free.
        lower = current - window
        upper = current + window
        return lower <= moment <= upper
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def check_issuer(response, allowed):
    """Return True only for an exact, case-sensitive issuer whitelist match."""
    try:
        issuer = response["issuer"]
        # DEFECT-7 FIX: plain membership uses exact equality; never endswith
        # or case-folded suffix matching that "evil-tsa.trusted.example"
        # or "trusted.example" would slip through.
        return isinstance(issuer, str) and issuer in list(allowed)
    except (KeyError, TypeError):
        return False


def verify_signature(response, key):
    """Verify the response HMAC-SHA256 signature in constant time.

    Compare the expected and supplied signatures with hmac.compare_digest.
    Any change to algorithm, digest, serial, time or issuer must invalidate the
    signature.  Malformed signatures are rejected without raising.
    """
    try:
        canonical = {
            "algorithm": response["algorithm"],
            "digest": response["digest"],
            "issuer": response["issuer"],
            "serial": response["serial"],
            "time": _canonical_time(response["time"]),
        }
        encoded = json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        expected = hmac.new(key, encoded, hashlib.sha256).hexdigest()

        supplied = response.get("signature")
        if not isinstance(supplied, str):
            supplied = ""
        # DEFECT-8 FIX: constant-time comparison via the hmac module attribute
        # (so runtime monkeypatching is observable), reached on both the
        # accepted and the rejected/mismatched path.
        return hmac.compare_digest(expected, supplied)
    except (KeyError, TypeError, ValueError):
        # Malformed response/signature/key material is rejected, never raised.
        return False


def record_serial(store, response):
    """Atomically append a serial to the ledger and return a result mapping.

    The success result is
    {"accepted": True, "reason": None, "max_serial": <serial>, "used": [...]}.

    A duplicate or non-increasing serial is rejected without changing the
    ledger and returns
    {"accepted": False, "reason": "serial_reuse", "max_serial": <old>,
     "used": [...]}.  The ledger change must be written to disk so a fresh
    process observes it.
    """
    serial = response.get("serial")
    ledger = _load_ledger(store)
    old_max = ledger["max_serial"]
    old_used = list(ledger["used"])

    # DEFECT-4 FIX: reject both rollback/non-increase and any serial already
    # present in the used set (replay), without touching the ledger file.
    duplicate_or_rollback = (
        not _is_positive_int(serial)
        or serial <= old_max
        or serial in old_used
    )
    if duplicate_or_rollback:
        return {
            "accepted": False,
            "reason": "serial_reuse",
            "max_serial": old_max,
            "used": old_used,
        }

    new_used = old_used + [serial]
    new_max = serial if serial > old_max else old_max
    # DEFECT-9 FIX: persist through an atomic replace on every accepted record
    # so a fresh process / new ledger handle observes the new state.
    _write_ledger_atomic(store, new_max, new_used)
    return {
        "accepted": True,
        "reason": None,
        "max_serial": new_max,
        "used": new_used,
    }


def _serial_allowed_in_view(serial, ledger):
    """check_serial's rule applied to an in-memory private ledger view."""
    return (
        _is_positive_int(serial)
        and serial > ledger["max_serial"]
        and serial not in ledger["used"]
    )


def tsa_batch(responses, policy, now):
    """Validate raw responses independently and return a batch report.

    policy contains store (a ledger path), allowed_issuers, window, key and
    documents (a mapping from integer serial to the original document bytes).
    Responses are processed in order against a private view of the ledger, and
    accepted serials are persisted once.  A bad response must not prevent later
    responses from being checked.  Duplicate serials inside the batch are
    rejected after the first accepted occurrence.

    The report is
    {"results": [{"index": i, "serial": int | None, "accepted": bool,
                  "reason": str | None}, ...],
     "accepted": [serial, ...],
     "rejected": [serial, ...]}.
    """
    store = policy["store"]
    # DEFECT-10 FIX: every batch gets its own fresh, disk-backed private view
    # loaded from THIS policy's store.  There is no shared/global serial record
    # that a previous response or batch could leak into the next one.
    view = _load_ledger(store)

    results = []
    accepted_serials = []
    rejected_serials = []

    for index, raw in enumerate(responses):
        serial_out = None
        accepted = False
        reason = "malformed_response"

        try:
            # Each raw response is parsed and verified independently; an
            # exception for this item only rejects this item.
            response = parse_response(raw)
            candidate = response.get("serial")
            if isinstance(candidate, int) and not isinstance(candidate, bool):
                serial_out = candidate

            document = policy["documents"].get(candidate)

            # Same evaluation order as the individual verification chain.
            if document is None:
                reason = "unknown_document"
            elif not check_imprint(response, document):
                reason = "imprint_mismatch"
            elif not check_time(response, now, policy["window"]):
                reason = "invalid_time"
            elif not check_issuer(response, policy["allowed_issuers"]):
                reason = "untrusted_issuer"
            elif not verify_signature(response, policy["key"]):
                reason = "invalid_signature"
            elif not _serial_allowed_in_view(candidate, view):
                # In-batch duplicates land here after the first occurrence was
                # committed to the private view.
                reason = "serial_reuse"
            else:
                accepted = True
                reason = None
        except Exception:
            accepted = False
            reason = "malformed_response"

        if accepted and serial_out is not None:
            # Commit immediately to the private view so a later duplicate in
            # the same batch is rejected, but do not touch disk per item.
            view["used"].append(serial_out)
            if serial_out > view["max_serial"]:
                view["max_serial"] = serial_out
            accepted_serials.append(serial_out)
        elif serial_out is not None:
            rejected_serials.append(serial_out)

        results.append(
            {
                "index": index,
                "serial": serial_out,
                "accepted": accepted,
                "reason": None if accepted else reason,
            }
        )

    # Persist the private view exactly once, after all items are processed.
    _write_ledger_atomic(store, view["max_serial"], view["used"])

    return {
        "results": results,
        "accepted": accepted_serials,
        "rejected": rejected_serials,
    }