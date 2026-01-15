# Security Policy

Thank you for reporting security issues responsibly.

## Supported Versions

Security fixes are provided for the **latest released version only**.
Please verify the issue on the latest version before reporting.

## Reporting a Vulnerability

**Do not report security vulnerabilities via public GitHub issues.**

We primarily use GitHub's **Private Vulnerability Reporting**.
Please click the **"Report a vulnerability"** button in the **Security** tab of this repository.

If you cannot use GitHub, you may contact us at: `support@fastfilelink.com`

> Please **do not** include sensitive exploit details in plain-text email. Ask for a secure channel first, and we will coordinate an appropriate method with you.

Include as much as you can:
- Affected version(s), OS/arch (and browser if relevant)
- Clear steps to reproduce (or a minimal PoC)
- Impact (what an attacker can achieve)
- Any relevant logs (please redact secrets)

## Coordinated Disclosure

Please keep vulnerability details private until a fix is released.
Once addressed, we will publish release notes and/or a GitHub Security Advisory as appropriate.

## Scope

### In scope
- Vulnerabilities in the `ffl` CLI codebase and its official release artifacts (including installers/update mechanisms).
- Cryptographic or logic issues in the End-to-End Encryption (E2EE) implementation.
- Unauthorized access issues (e.g., auth bypass, path traversal, IDOR) in the file serving logic.

### Out of scope
- Vulnerabilities in the underlying OS, local network configuration, or unrelated third-party services.
- Testing against public production infrastructure (e.g., `*.fastfilelink.com` relays) **without prior written authorization**. Please test against a local instance or your own self-hosted relay.
- Denial-of-Service (DoS) attacks or resource exhaustion testing.
- Social engineering or phishing attacks against users.

## Safe Harbor

Good-faith security research is welcome.
We pledge not to initiate legal action against researchers for penetrating or attempting to penetrate our systems as long as they adhere to this policy.

Please avoid accessing data that isn’t yours, disrupting services for other users, or destroying data.
