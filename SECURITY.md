# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Report it privately through GitHub:
**Security tab → "Report a vulnerability"** on https://github.com/putridpunk/CipherCheck/security/advisories/new

Include what you found, how to reproduce it, the version (`ciphercheck-cli --version`) and your operating system. **Never include a real password.** I aim to acknowledge reports within a few days; this is a hobby project, so there is no guaranteed response time.

## What counts

CipherCheck is a local, offline tool. Examples of issues worth reporting:

- anything that makes it send data over the network, or write a password (or a fragment of one) to a file, log, report or the clipboard when it should not;
- a way a crafted input file (for example in the Audit tab) can crash it, run code or leak data;
- a defect in the executables or the build workflow that could let someone tamper with a release.

Not security issues: weak-password verdicts that you disagree with, translation mistakes, or the "unsigned executable" warning from Windows or macOS (the binaries are not code-signed; compare them with `SHA256SUMS.txt` in each release).

## Supported versions

Only the latest release receives fixes.
