"""CLI for sdjwt-offline."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from sdjwt_offline.core import (
    BitstringStatusList,
    create_presentation,
    issue_sd_jwt,
    make_hmac_signer,
    pack_qr_payload,
    unpack_qr_payload,
    verify_sd_jwt,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sdjwt-offline",
        description="Zero-network RFC 9901 SD-JWT & W3C Bitstring Status List offline verifier.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="Issue, selectively disclose, QR-pack, verify, and revoke a demo credential")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "demo":
        sign_fn, verify_fn = make_hmac_signer(b"codesphere-demo-issuer-key-32byt")
        cred = issue_sd_jwt(
            issuer="did:web:uneb.go.ug",
            subject="did:example:student-2026-091",
            public_claims={"credential_type": "AcademicTranscript"},
            disclosable_claims={
                "full_name": "Amina Namono",
                "national_id": "CF99012345678X",
                "degree": "BSc Computer Science",
                "honors": "First Class",
            },
            sign_fn=sign_fn,
            status_index=42,
        )
        pres = create_presentation(cred, {"degree", "honors"})
        qr = pack_qr_payload(pres)
        unpacked = unpack_qr_payload(qr)

        status_list = BitstringStatusList(1024)
        before_rev = verify_sd_jwt(
            unpacked,
            verify_fn=verify_fn,
            expected_issuer="did:web:uneb.go.ug",
            status_list=status_list,
        )
        status_list.revoke(42)
        after_rev = verify_sd_jwt(
            unpacked,
            verify_fn=verify_fn,
            expected_issuer="did:web:uneb.go.ug",
            status_list=status_list,
        )
        print(
            json.dumps(
                {
                    "qr_length_bytes": len(qr),
                    "before_revocation_valid": before_rev.valid,
                    "disclosed_claims": before_rev.disclosed_claims,
                    "hidden_digests_count": before_rev.undisclosed_digest_count,
                    "after_revocation_valid": after_rev.valid,
                    "after_revocation_flag": after_rev.revoked,
                },
                indent=2,
            )
        )
        return 0 if (before_rev.valid and after_rev.revoked and not after_rev.valid) else 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
