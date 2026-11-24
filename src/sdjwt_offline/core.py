"""IETF RFC 9901 Selective-Disclosure JWT (SD-JWT) & W3C Bitstring Status List offline engine."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def disclosure_digest(encoded_disclosure: str) -> str:
    """Compute RFC 9901 SHA-256 base64url digest of an ASCII base64url-encoded disclosure."""
    return b64url_encode(hashlib.sha256(encoded_disclosure.encode("ascii")).digest())


def make_hmac_signer(secret_key: bytes) -> tuple[Callable[[bytes], bytes], Callable[[bytes, bytes], bool]]:
    """Return constant-time HS256 (sign, verify) callables for symmetric issuer/verifier setups."""
    if len(secret_key) < 32:
        raise ValueError("HS256 signing key must be at least 32 bytes (256-bit)")

    def _sign(signing_input: bytes) -> bytes:
        return hmac.new(secret_key, signing_input, hashlib.sha256).digest()

    def _verify(signing_input: bytes, signature: bytes) -> bool:
        expected = hmac.new(secret_key, signing_input, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)

    return _sign, _verify


class BitstringStatusList:
    """W3C Bitstring Status List v1.0 compact zlib-compressed offline revocation bitmap."""

    def __init__(self, size: int = 16_384) -> None:
        if size < 8 or size % 8 != 0:
            raise ValueError("Bitstring size must be a positive multiple of 8")
        self.size = size
        self._bits = bytearray(size // 8)

    def revoke(self, index: int) -> None:
        self._check_index(index)
        self._bits[index // 8] |= 1 << (7 - (index % 8))

    def reinstate(self, index: int) -> None:
        self._check_index(index)
        self._bits[index // 8] &= ~(1 << (7 - (index % 8)))

    def is_revoked(self, index: int) -> bool:
        self._check_index(index)
        return bool(self._bits[index // 8] & (1 << (7 - (index % 8))))

    def encode(self) -> str:
        """Compress the bitstring with zlib deflate and base64url-encode it."""
        return b64url_encode(zlib.compress(bytes(self._bits), level=9))

    @classmethod
    def decode(cls, encoded: str) -> BitstringStatusList:
        raw = zlib.decompress(b64url_decode(encoded))
        inst = cls(size=len(raw) * 8)
        inst._bits = bytearray(raw)
        return inst

    def _check_index(self, index: int) -> None:
        if not 0 <= index < self.size:
            raise IndexError(f"Status list index {index} out of range [0, {self.size})")


@dataclass(frozen=True)
class SdJwtCredential:
    """Issued SD-JWT containing the signed JWT plus all holder-retained claim disclosures."""

    jwt: str
    disclosures: dict[str, str]
    compact_token: str


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    issuer: str | None
    subject: str | None
    disclosed_claims: dict[str, Any]
    undisclosed_digest_count: int
    revoked: bool
    errors: tuple[str, ...]


def issue_sd_jwt(
    *,
    issuer: str,
    subject: str,
    public_claims: dict[str, Any],
    disclosable_claims: dict[str, Any],
    sign_fn: Callable[[bytes], bytes],
    alg: str = "HS256",
    ttl_seconds: int = 86_400 * 365,
    decoy_count: int = 2,
    status_index: int | None = None,
    now_epoch: int | None = None,
) -> SdJwtCredential:
    """Issue an RFC 9901 SD-JWT with salted SHA-256 claim disclosures and privacy decoy digests."""
    now = int(now_epoch if now_epoch is not None else time.time())
    disclosures: dict[str, str] = {}
    sd_digests: list[str] = []

    for claim_name, claim_val in sorted(disclosable_claims.items()):
        salt = b64url_encode(secrets.token_bytes(16))
        encoded_disc = b64url_encode(_canonical_json([salt, claim_name, claim_val]))
        disclosures[claim_name] = encoded_disc
        sd_digests.append(disclosure_digest(encoded_disc))

    for _ in range(max(0, decoy_count)):
        decoy_bytes = secrets.token_bytes(32)
        sd_digests.append(b64url_encode(hashlib.sha256(decoy_bytes).digest()))

    sd_digests.sort()

    header = {"alg": alg, "typ": "vc+sd-jwt"}
    payload: dict[str, Any] = {
        **public_claims,
        "iss": issuer,
        "sub": subject,
        "iat": now,
        "exp": now + ttl_seconds,
        "_sd_alg": "sha-256",
        "_sd": sd_digests,
    }
    if status_index is not None:
        payload["status"] = {"status_list": {"idx": status_index}}

    header_b64 = b64url_encode(_canonical_json(header))
    payload_b64 = b64url_encode(_canonical_json(payload))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig_b64 = b64url_encode(sign_fn(signing_input))
    jwt_str = f"{header_b64}.{payload_b64}.{sig_b64}"

    parts = [jwt_str, *disclosures.values(), ""]
    return SdJwtCredential(
        jwt=jwt_str,
        disclosures=disclosures,
        compact_token="~".join(parts),
    )


def create_presentation(credential: SdJwtCredential, reveal_claims: list[str] | set[str]) -> str:
    """Create a holder selective-disclosure presentation revealing ONLY `reveal_claims`."""
    selected = [credential.disclosures[k] for k in sorted(reveal_claims) if k in credential.disclosures]
    return "~".join([credential.jwt, *selected, ""])


def verify_sd_jwt(
    presentation: str,
    *,
    verify_fn: Callable[[bytes, bytes], bool],
    expected_issuer: str | None = None,
    status_list: BitstringStatusList | None = None,
    now_epoch: int | None = None,
) -> VerificationResult:
    """Offline-verify an SD-JWT presentation signature, expiry, revocation bitstring & disclosures."""
    errors: list[str] = []
    parts = presentation.split("~")
    if len(parts) < 2:
        return VerificationResult(False, None, None, {}, 0, False, ("Malformed SD-JWT framing",))

    jwt_str = parts[0]
    raw_disclosures = [p for p in parts[1:] if p]
    jwt_segs = jwt_str.split(".")
    if len(jwt_segs) != 3:
        return VerificationResult(False, None, None, {}, 0, False, ("Malformed JWT segment count",))

    header_b64, payload_b64, sig_b64 = jwt_segs
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        sig_bytes = b64url_decode(sig_b64)
        payload = json.loads(b64url_decode(payload_b64).decode("utf-8"))
    except Exception as exc:
        return VerificationResult(False, None, None, {}, 0, False, (f"Decode failure: {exc}",))

    if not verify_fn(signing_input, sig_bytes):
        errors.append("Cryptographic signature verification failed")

    iss = payload.get("iss")
    sub = payload.get("sub")
    if expected_issuer is not None and iss != expected_issuer:
        errors.append(f"Issuer mismatch: expected '{expected_issuer}', got '{iss}'")

    now = int(now_epoch if now_epoch is not None else time.time())
    exp = payload.get("exp")
    if isinstance(exp, int) and now > exp:
        errors.append(f"Credential expired at epoch {exp} (now={now})")

    if payload.get("_sd_alg", "sha-256") != "sha-256":
        errors.append(f"Unsupported _sd_alg '{payload.get('_sd_alg')}'")

    revoked = False
    status_info = (payload.get("status") or {}).get("status_list") or {}
    if status_list is not None and isinstance(status_info.get("idx"), int):
        idx = int(status_info["idx"])
        if status_list.is_revoked(idx):
            revoked = True
            errors.append(f"Credential revoked in offline BitstringStatusList at index {idx}")

    allowed_digests = set(payload.get("_sd") or [])
    if len(allowed_digests) != len(payload.get("_sd") or []):
        errors.append("Duplicate digest detected in _sd array")

    disclosed: dict[str, Any] = {
        k: v for k, v in payload.items() if k not in ("_sd", "_sd_alg", "status")
    }
    matched_digests: set[str] = set()
    for disc in raw_disclosures:
        dig = disclosure_digest(disc)
        if dig not in allowed_digests:
            errors.append("Presented disclosure digest does not match any issuer-signed _sd hash")
            continue
        if dig in matched_digests:
            errors.append("Duplicate disclosure presented")
            continue
        try:
            decoded = json.loads(b64url_decode(disc).decode("utf-8"))
        except Exception as exc:
            errors.append(f"Malformed disclosure JSON: {exc}")
            continue
        if not isinstance(decoded, list) or len(decoded) != 3 or not isinstance(decoded[1], str):
            errors.append("Disclosure must be a 3-element array [salt, claim_name, claim_value]")
            continue
        claim_name = decoded[1]
        if claim_name in ("_sd", "...", "iss", "sub", "exp", "iat"):
            errors.append(f"Forbidden reserved claim name '{claim_name}' in disclosure")
            continue
        disclosed[claim_name] = decoded[2]
        matched_digests.add(dig)

    undisclosed = max(0, len(allowed_digests) - len(matched_digests))
    return VerificationResult(
        valid=(len(errors) == 0),
        issuer=str(iss) if iss is not None else None,
        subject=str(sub) if sub is not None else None,
        disclosed_claims=disclosed,
        undisclosed_digest_count=undisclosed,
        revoked=revoked,
        errors=tuple(errors),
    )


def pack_qr_payload(presentation: str) -> str:
    """Compress an SD-JWT presentation with zlib into a compact `SDQR1:` QR-friendly ASCII string."""
    compressed = zlib.compress(presentation.encode("ascii"), level=9)
    return "SDQR1:" + b64url_encode(compressed)


def unpack_qr_payload(qr_text: str) -> str:
    """Decode a compact `SDQR1:` QR payload back into an RFC 9901 SD-JWT presentation."""
    if not qr_text.startswith("SDQR1:"):
        raise ValueError("QR payload must start with 'SDQR1:'")
    return zlib.decompress(b64url_decode(qr_text[6:])).decode("ascii")
