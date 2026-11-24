"""Five behaviour tests for end-to-end timestamp response verification."""

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
    parse_response,
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


def _policy(store, documents):
    return {
        "store": store,
        "allowed_issuers": [ISSUER],
        "window": WINDOW,
        "key": KEY,
        "documents": documents,
    }


def test_valid_response_passes_every_check(tmp_path):
    raw = _raw(serial=1000)
    response = parse_response(raw)
    digest = hashlib.sha256(DOCUMENT).hexdigest()

    assert response["algorithm"] == "sha256"
    assert response["digest"] == digest
    assert response["serial"] == 1000
    assert response["time"] == NOW
    assert response["time"].tzinfo is not None
    assert response["issuer"] == ISSUER
    assert response["signature"] == _signature(
        {
            "algorithm": "sha256",
            "digest": digest,
            "serial": 1000,
            "time": NOW,
            "issuer": ISSUER,
        }
    )

    assert check_imprint(response, DOCUMENT) is True
    assert check_time(response, NOW, WINDOW) is True
    assert check_issuer(response, [ISSUER]) is True
    assert verify_signature(response, KEY) is True

    ledger = tmp_path / "ledger.json"
    assert check_serial(response, ledger) is True
    recorded = record_serial(ledger, response)
    assert recorded["accepted"] is True
    assert recorded["max_serial"] == 1000
    assert check_serial(response, ledger) is False


def test_imprint_mismatch_is_rejected():
    other_document = b"different-evidence-payload"
    response = parse_response(_raw(serial=1100, document=other_document))

    assert check_imprint(response, other_document) is True
    assert check_imprint(response, DOCUMENT) is False


def test_serial_rollback_is_rejected(tmp_path):
    ledger = tmp_path / "ledger.json"
    assert record_serial(ledger, _parsed(serial=1200))["accepted"] is True

    assert check_serial(_parsed(serial=1199), ledger) is False
    assert check_serial(_parsed(serial=1200), ledger) is False
    assert check_serial(_parsed(serial=1201), ledger) is True


def test_expired_response_is_rejected():
    assert check_time(_parsed(time=NOW - WINDOW), NOW, WINDOW) is True
    assert check_time(_parsed(time=NOW + WINDOW), NOW, WINDOW) is True
    just_expired = NOW - WINDOW - timedelta(microseconds=1)
    assert check_time(_parsed(time=just_expired), NOW, WINDOW) is False
    assert check_time(_parsed(time=NOW - timedelta(days=1)), NOW, WINDOW) is False


def test_two_batches_match_individual_verification(tmp_path):
    raws = [_raw(serial=1300), _raw(serial=1301), _raw(serial=1301)]
    documents = {1300: DOCUMENT, 1301: DOCUMENT}

    first_ledger = tmp_path / "batch-first.json"
    second_ledger = tmp_path / "batch-second.json"
    first = tsa_batch(raws, _policy(first_ledger, documents), NOW)
    second = tsa_batch(raws, _policy(second_ledger, documents), NOW)

    first_flags = [item["accepted"] for item in first["results"]]
    second_flags = [item["accepted"] for item in second["results"]]
    assert [item["index"] for item in first["results"]] == [0, 1, 2]
    assert first_flags == [True, True, False]
    assert second_flags == first_flags
    assert first["accepted"] == [1300, 1301]
    assert first["rejected"] == [1301]

    expected_ledger = tmp_path / "expected.json"
    expected_flags = []
    for raw in raws:
        response = parse_response(raw)
        accepted = (
            check_imprint(response, DOCUMENT)
            and check_time(response, NOW, WINDOW)
            and check_issuer(response, [ISSUER])
            and verify_signature(response, KEY)
            and check_serial(response, expected_ledger)
        )
        if accepted:
            accepted = record_serial(expected_ledger, response)["accepted"]
        expected_flags.append(accepted)

    assert expected_flags == first_flags
    assert second_flags == expected_flags

    for ledger in (first_ledger, second_ledger, expected_ledger):
        state = json.loads(ledger.read_text(encoding="utf-8"))
        assert state["max_serial"] == 1301
        assert set(state["used"]) == {1300, 1301}