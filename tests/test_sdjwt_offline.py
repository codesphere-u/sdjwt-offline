"""Tests for RFC 9901 SD-JWT selective disclosure, tamper rejection, Bitstring revocation & QR."""

from __future__ import annotations

import json

import pytest

from sdjwt_offline import (
    BitstringStatusList,
    create_presentation,
    issue_sd_jwt,
    make_hmac_signer,
    pack_qr_payload,
    unpack_qr_payload,
    verify_sd_jwt,
)
from sdjwt_offline.cli import main as cli_main


def test_selective_disclosure_hides_unrevealed_claims_and_qr_roundtrips() -> None:
    sign_fn, verify_fn = make_hmac_signer(b"0123456789abcdef0123456789abcdef")
    cred = issue_sd_jwt(
        issuer="did:web:aid.org",
        subject="beneficiary-007",
        public_claims={"program": "FoodVoucher"},
        disclosable_claims={"household_size": 5, "national_id": "NIN-998877", "district": "Gulu"},
        sign_fn=sign_fn,
        decoy_count=3,
        status_index=17,
        now_epoch=1_764_000_000,
    )
    pres = create_presentation(cred, {"district"})
    assert "NIN-998877" not in pres

    qr = pack_qr_payload(pres)
    assert qr.startswith("SDQR1:")
    assert unpack_qr_payload(qr) == pres

    res = verify_sd_jwt(
        pres,
        verify_fn=verify_fn,
        expected_issuer="did:web:aid.org",
        now_epoch=1_764_000_100,
    )
    assert res.valid is True
    assert res.disclosed_claims["district"] == "Gulu"
    assert "national_id" not in res.disclosed_claims
    assert res.undisclosed_digest_count == 5


def test_tampered_disclosure_expired_token_and_revocation_bitstring_rejected() -> None:
    sign_fn, verify_fn = make_hmac_signer(b"abcdef0123456789abcdef0123456789")
    _, wrong_verify = make_hmac_signer(b"99999999999999999999999999999999")
    cred = issue_sd_jwt(
        issuer="did:web:board.org",
        subject="lic-1",
        public_claims={},
        disclosable_claims={"license_no": "MED-100"},
        sign_fn=sign_fn,
        ttl_seconds=60,
        status_index=9,
        now_epoch=1_000_000,
    )
    pres = create_presentation(cred, {"license_no"})

    assert verify_sd_jwt(pres, verify_fn=wrong_verify, now_epoch=1_000_010).valid is False
    assert verify_sd_jwt(pres, verify_fn=verify_fn, now_epoch=1_000_120).valid is False

    sl = BitstringStatusList(1024)
    sl.revoke(9)
    reloaded = BitstringStatusList.decode(sl.encode())
    assert reloaded.is_revoked(9) is True
    assert reloaded.is_revoked(10) is False

    rev_res = verify_sd_jwt(pres, verify_fn=verify_fn, status_list=reloaded, now_epoch=1_000_010)
    assert rev_res.valid is False
    assert rev_res.revoked is True

    with pytest.raises(ValueError):
        unpack_qr_payload("INVALID:123")


def test_cli_demo(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main(["demo"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["before_revocation_valid"] is True
    assert out["after_revocation_valid"] is False
    assert out["after_revocation_flag"] is True
