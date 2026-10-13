# Security Policy

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Use [GitHub private vulnerability reporting](https://github.com/consealdev/conseal/security/advisories/new) to submit a report confidentially. If you are unsure whether something qualifies, err on the side of reporting privately.

You can expect:

- **Acknowledgement within 7 days** of receipt.
- **Status update within 30 days** — either a fix timeline or a decision that the report is out of scope.
- **Credit in the release notes** for valid reports, unless you prefer to remain anonymous.
- No public disclosure until a patch is available, or by mutual agreement.

---

## Scope

### In scope

- Incorrect use of `SubtleCrypto` that weakens confidentiality, integrity, or authenticity guarantees
- Key material reachable by JavaScript code contrary to the documented `extractable: false` guarantee
- PBKDF2 iteration count, salt handling, or IV reuse that reduces brute-force resistance below documented levels
- AES-GCM authentication tag bypass — any path where tampered ciphertext decrypts without throwing
- Incorrect ECDH / ECDSA wiring — shared secret derivation or signature verification that produces wrong results
- BIP-39 mnemonic generation producing insufficient entropy or a biased word distribution

### Out of scope

The following are known limitations documented in the [threat model](./threat-model.md) and are not eligible for reports:

- XSS attacks against the host application — conseal cannot protect against arbitrary JavaScript in the same origin
- Weak passphrases — entropy validation is an application responsibility
- Side-channel attacks (Spectre, timing) against `SubtleCrypto` — mitigations are the browser vendor's responsibility
- Loss of the Secret Key or mnemonic leading to permanent data inaccessibility — this is by design
- Transport security — conseal does not manage HTTP connections
- Features not yet implemented

---

## Preferred languages

English.

---

## Bug bounty

There is no formal bounty programme at this time. Conseal is pre-v1.0 and independently developed. Valid cryptographic vulnerabilities will be acknowledged publicly in the changelog. A formal bounty programme is planned before or at v1.0.
