# Security policy

crit is a static analysis tool; this policy covers vulnerabilities in **crit
itself** (for example, a crafted input file that could cause unsafe behavior in
the scanner), not findings crit reports about other code.

## Reporting a vulnerability

Please report suspected vulnerabilities privately rather than in a public issue.

- **Contact:** `<security contact — set on handover, e.g. a security distribution list or the owning team's intake>`
- Include: affected version/commit, a description, and a minimal reproduction
  (a sample input file and the command run) where possible.
- You can expect an acknowledgement and, once triaged, a remediation plan and
  disclosure timeline.

## Scope

In scope:

- Memory-safety or panic-to-DoS issues in the scanner or its grammar loading.
- Path handling that escapes the intended scan root.
- Issues in the runtime grammar loader (`[[grammars]]` shared libraries) that
  could be abused by a malicious grammar path in configuration.

Out of scope:

- False positives / false negatives in rules — file those as normal issues.
- Vulnerabilities in the code crit is *scanning*.

## Supported versions

Until a formal release cadence is established, only the tip of the default
branch is supported.
