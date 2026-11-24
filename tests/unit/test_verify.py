"""Ten contract tests for the timestamp-authority response verifier."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

from tsa.verify import (
    check_imprint,
    check_issuer,
    check_serial,
    check_time,
    record_serial,
    tsa_batch,
    verify_signature,
)

NOW = datetime(2026, 11, 19, 12, 0, 0, tzinfo=timezone.utc)
WINDOW = timedelta(minutes=5)
DOCUMENT = b"evidence-payload-2026-11-19"
KEY = b"tsa-hmac-key-v1"
ISSUER = "tsa.trusted.example"


def _utc_text(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return value


def _signature(fields, key=KEY):
    canonical = {
        "algorithm": fields["algorithm"],
        "digest": fields["digest"],
        "issuer": fields["issuer"],
        "serial": fields["serial"],
        "time": _utc_text(fields["time"]),
    }
    encoded = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hmac.new(key, encoded, hashlib.sha256).hexdigest()


def _parsed(
    *,
    algorithm="sha256",
    document=DOCUMENT,
    serial=100,
    time=NOW,
    issuer=ISSUER,
    digest=None,
    signature=None,
    key=KEY,
):
    if digest is None:
        digest = hashlib.new(algorithm, document).hexdigest()
    fields = {
        "algorithm": algorithm,
        "digest": digest,
        "serial": serial,
        "time": time,
        "issuer": issuer,
    }
    if signature is None:
        signature = _signature(fields, key)
    return {
        "algorithm": algorithm,
        "digest": digest,
        "serial": serial,
        "time": time,
        "issuer": issuer,
        "signature": signature,
    }


def _raw(
    *,
    algorithm="sha256",
    document=DOCUMENT,
    serial=100,
    time=NOW,
    issuer=ISSUER,
    digest=None,
    signature=None,
    key=KEY,
):
    if digest is None:
        digest = hashlib.new(algorithm, document).hexdigest()
    fields = {
        "algorithm": algorithm,
        "digest": digest,
        "serial": serial,
        "time": _utc_text(time),
        "issuer": issuer,
    }
    if signature is None:
        signature = _signature(fields, key)
    body = dict(fields)
    body["signature"] = signature
    return json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _write_ledger(path, max_serial, used):
    path.write_text(
        json.dumps({"max_serial": max_serial, "used": used}),
        encoding="utf-8",
    )


def test_digest_comparison_requires_full_digest_not_length():
    assert check_imprint(_parsed(), DOCUMENT) is True
    forged = _parsed(digest="0" * 64)
    assert len(forged["digest"]) == 64
    assert check_imprint(forged, DOCUMENT) is False


def test_digest_uses_declared_algorithm_after_migration():
    document = b"algorithm-migration-payload"
    assert check_imprint(_parsed(algorithm="sha512", document=document), document) is True
    assert check_imprint(_parsed(algorithm="sha384", document=document), document) is True


def test_serial_must_be_strictly_greater_than_ledger_max(tmp_path):
    ledger = tmp_path / "ledger.json"
    _write_ledger(ledger, 100, [90, 100])
    assert check_serial(_parsed(serial=100), ledger) is False
    assert check_serial(_parsed(serial=99), ledger) is False
    assert check_serial(_parsed(serial=0), ledger) is False
    assert check_serial(_parsed(serial=101), ledger) is True


def test_same_serial_cannot_be_recorded_twice(tmp_path):
    ledger = tmp_path / "ledger.json"
    first = record_serial(ledger, _parsed(serial=500))
    assert first["accepted"] is True
    assert first["max_serial"] == 500
    assert check_serial(_parsed(serial=500), ledger) is False

    replay = record_serial(ledger, _parsed(serial=500))
    assert replay["accepted"] is False
    assert replay["reason"] == "serial_reuse"

    state = json.loads(ledger.read_text(encoding="utf-8"))
    assert state["max_serial"] == 500
    assert state["used"].count(500) == 1


def test_future_timestamp_outside_window_is_rejected():
    assert check_time(_parsed(time=NOW + timedelta(days=1)), NOW, WINDOW) is False
    just_outside = NOW + WINDOW + timedelta(seconds=1)
    assert check_time(_parsed(time=just_outside), NOW, WINDOW) is False


def test_zero_length_window_is_rejected():
    assert check_time(_parsed(time=NOW), NOW, timedelta(0)) is False
    assert check_time(_parsed(time=NOW), NOW, timedelta(seconds=-1)) is False


def test_issuer_whitelist_uses_exact_match_not_suffix():
    assert check_issuer(_parsed(issuer=ISSUER), [ISSUER]) is True
    forged_names = (
        "evil-" + ISSUER,
        "not" + ISSUER,
        "trusted.example",
        ISSUER.upper(),
    )
    for forged in forged_names:
        assert check_issuer(_parsed(issuer=forged), [ISSUER]) is False


def test_signature_comparison_uses_constant_time_digest(monkeypatch):
    response = _parsed(serial=900)
    observed = []
    real_compare = hmac.compare_digest

    def spy(left, right):
        observed.append((left, right))
        return real_compare(left, right)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    assert verify_signature(response, KEY) is True
    assert observed, "verify_signature must compare with hmac.compare_digest"

    tampered = dict(response)
    tampered["serial"] = 901
    assert verify_signature(tampered, KEY) is False

    forged = dict(response)
    forged["signature"] = "0" * 64
    observed.clear()
    assert verify_signature(forged, KEY) is False
    assert observed, "the rejected path must also use hmac.compare_digest"


def test_serial_ledger_persists_across_restart(tmp_path):
    ledger = tmp_path / "ledger.json"
    assert record_serial(ledger, _parsed(serial=700))["accepted"] is True
    assert ledger.exists()

    persisted = json.loads(ledger.read_text(encoding="utf-8"))
    assert persisted["max_serial"] == 700
    assert 700 in persisted["used"]

    after_restart = tmp_path / "ledger.json"
    assert check_serial(_parsed(serial=700), after_restart) is False
    assert check_serial(_parsed(serial=699), after_restart) is False
    assert record_serial(after_restart, _parsed(serial=700))["accepted"] is False
    assert check_serial(_parsed(serial=701), after_restart) is True


def test_batch_keeps_each_response_serial_independent(tmp_path):
    documents = {810: DOCUMENT, 811: DOCUMENT, 812: DOCUMENT, 813: DOCUMENT}
    first_policy = {
        "store": tmp_path / "batch-a.json",
        "allowed_issuers": [ISSUER],
        "window": WINDOW,
        "key": KEY,
        "documents": documents,
    }
    first = tsa_batch(
        [_raw(serial=810), _raw(serial=811), _raw(serial=811)],
        first_policy,
        NOW,
    )
    assert [item["accepted"] for item in first["results"]] == [True, True, False]
    assert [item["serial"] for item in first["results"]] == [810, 811, 811]
    assert first["accepted"] == [810, 811]
    assert first["rejected"] == [811]
    assert check_serial(_parsed(serial=810), first_policy["store"]) is False

    second_policy = {
        "store": tmp_path / "batch-b.json",
        "allowed_issuers": [ISSUER],
        "window": WINDOW,
        "key": KEY,
        "documents": documents,
    }
    second = tsa_batch([_raw(serial=812), _raw(serial=813)], second_policy, NOW)
    assert [item["accepted"] for item in second["results"]] == [True, True]