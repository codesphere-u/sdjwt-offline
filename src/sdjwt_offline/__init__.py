"""sdjwt-offline — Zero-network RFC 9901 SD-JWT & W3C Bitstring Status List toolkit."""

from sdjwt_offline.core import (
    BitstringStatusList,
    SdJwtCredential,
    VerificationResult,
    create_presentation,
    disclosure_digest,
    issue_sd_jwt,
    make_hmac_signer,
    pack_qr_payload,
    unpack_qr_payload,
    verify_sd_jwt,
)

__version__ = "0.1.0"

__all__ = [
    "BitstringStatusList",
    "SdJwtCredential",
    "VerificationResult",
    "__version__",
    "create_presentation",
    "disclosure_digest",
    "issue_sd_jwt",
    "make_hmac_signer",
    "pack_qr_payload",
    "unpack_qr_payload",
    "verify_sd_jwt",
]
