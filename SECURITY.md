# Security Policy for NetScoutX

At NetScoutX, we take the security of our project and its users seriously. This document outlines our security policy, including how to report vulnerabilities, our supported versions, and our approach to security advisories.

## Supported Versions

The NetScoutX project is actively maintained. We provide security updates for the latest stable release. Users are strongly encouraged to always use the most recent version of NetScoutX to ensure they have the latest security fixes and features.

| Version | Supported          |
| :------ | :----------------- |
| `v1.0.0`  | :white_check_mark: |
| `< v1.0.0`| :x:                |

## Reporting a Vulnerability

We appreciate the efforts of security researchers and the community in helping us maintain a secure project. If you discover a security vulnerability in NetScoutX, please report it to us privately as soon as possible.

**Please DO NOT open a public GitHub issue for security vulnerabilities.**

To report a vulnerability, please send an email to:

**[hello@synth1ca.eu](mailto:hello@synth1ca.eu)**

In your report, please include:

*   A clear and concise description of the vulnerability.
*   Steps to reproduce the vulnerability.
*   The potential impact of the vulnerability.
*   Any proof-of-concept code or scripts.
*   Your contact information (optional, but appreciated for follow-up).

We will acknowledge your report within 48 hours and provide a more detailed response within 5 business days, outlining the next steps in our investigation.

## Disclosure Policy

Our disclosure policy is designed to protect our users while ensuring transparency:

1.  Upon receiving a vulnerability report, we will confirm receipt and begin an investigation.
2.  We will work to develop a fix for the vulnerability.
3.  Once a fix is ready, we will coordinate with the reporter (if they wish) on a disclosure timeline.
4.  We aim to disclose vulnerabilities publicly only after a fix has been released and sufficient time has passed for users to update.
5.  Public disclosure will typically be via a GitHub Security Advisory.

## Dependencies with Security Impact

NetScoutX relies on several third-party Go modules, most notably `github.com/google/gopacket` for packet capture and decoding. We monitor our dependencies for known vulnerabilities and update them regularly.

Users should be aware that `libpcap` (a system library NetScoutX depends on) is a critical component. Ensuring your system's `libpcap` installation is up-to-date is also important for overall security.

## Security Advisories

Security advisories for NetScoutX will be published on our GitHub repository under the "Security" tab, and will follow the GitHub Security Advisory format. These advisories will detail the vulnerability, affected versions, impact, and mitigation steps.

---
