# Architecture — `sdjwt-offline`

- `sdjwt_offline.core`: RFC 9901 salted SHA-256 `_sd` disclosure generator, decoy digest mixer, pluggable signer/verifier callables (built-in constant-time HS256 or caller-provided Ed25519/ES256), W3C zlib-compressed Bitstring Status List v1.0, and `SDQR1:` compact QR framing.
- `sdjwt_offline.cli`: End-to-end demo & verification CLI.
