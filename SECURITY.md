# Security Policy

## Supported Versions

Currently, the following versions of PyDivert are supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 3.0.x   | :white_check_mark: |
| < 3.0   | :x:                |

## Reporting a Vulnerability

If you discover a potential security vulnerability in PyDivert, please do **not** open a public issue. Instead, report it privately to the maintainers:

- Fabio Falcinelli: [fabio.falcinelli@gmail.com](mailto:fabio.falcinelli@gmail.com)

We aim to acknowledge receipt of your report as soon as possible (typically within a few business days). Please note that while we take security seriously, we are a community-maintained project and cannot guarantee a specific resolution timeframe. We will provide updates as we investigate the issue and work toward a fix.

### What to Include in a Report

To help us address the issue quickly, please include:
- A clear description of the vulnerability.
- A minimal reproducible example (PoC) if possible.
- Any potential impact or exploitation scenarios.

## Security Best Practices for PyDivert Users

PyDivert interacts with the low-level Windows network stack and requires administrator privileges to function. To ensure your application remains secure:

1.  **Principle of Least Privilege**: Run only the necessary parts of your application with administrator privileges.
2.  **Input Validation**: If your application processes network packets based on external input, ensure all inputs are strictly validated before being used in filter strings or packet modifications.
3.  **Sanitize Packet Data**: Be cautious when modifying packet payloads, especially when dealing with protocols that may have complex parsing requirements.
4.  **Keep WinDivert Updated**: PyDivert bundles specific versions of the WinDivert driver and DLL. Ensure you are using the latest version of PyDivert to benefit from upstream security fixes in WinDivert itself.

## Disclosure Policy

We follow a responsible disclosure policy:
1.  Acknowledge the report.
2.  Investigate and confirm the vulnerability.
3.  Work on a fix.
4.  Release a new version with the fix.
5.  Publicly disclose the vulnerability (e.g., via GitHub Security Advisories) after a fix is available and users have had time to update.
