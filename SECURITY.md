# Security Policy

## Supported versions

Security fixes are provided for the latest published minor release. Users should
upgrade to the newest patch before reporting a problem.

| Version              | Supported |
| -------------------- | :-------: |
| Latest `0.x` release |    Yes    |
| Older releases       |    No     |

## Reporting a vulnerability

Do not open a public issue or discussion for a suspected vulnerability.

Use GitHub's
[private vulnerability reporting](https://github.com/ThreatFlux/threatflux-threat-detection/security/advisories/new).
If that is unavailable, email `security@threatflux.ai` with the repository name
in the subject.

Include, when possible:

- affected versions, features, and detection engines;
- impact and realistic attack conditions;
- a minimal reproducer, described rather than attached if it is live malware;
- suggested mitigations; and
- whether the issue is already public.

Remove credentials, personal information, and unrelated production data. Encrypt
especially sensitive material before sending it and ask for a preferred key or
transfer method.

We aim to acknowledge reports within three business days. Validation,
remediation, disclosure timing, and credit are coordinated privately. Please
allow a reasonable remediation window before public disclosure.

## Security model

This crate parses and pattern-matches untrusted input. It is a detection aid,
not a containment boundary. Applications remain responsible for:

- treating scanned input as hostile and running scans in an isolated process,
  container, or VM. Nothing here sandboxes a sample;
- treating a clean result as inconclusive. Engine failures are logged and
  skipped, `scan_directory` does not walk a tree, and `max_file_size` and
  `max_concurrent_scans` are not enforced by the engines, so callers must bound
  input size and concurrency themselves;
- vetting external rule sources. With `rule-management`, rules are fetched over
  the network and compiled; a hostile rule source is a code-execution and
  denial-of-service risk;
- securing the ClamAV socket or host used by `clamav-engine`, which is an
  external trust dependency; and
- bounding resource use. Pattern and YARA matching on adversarial input can be
  slow, and pattern matching reads the whole target into memory.

## Dependency disclosures

Reports that only repeat a dependency advisory should explain whether the
vulnerable code is reachable in this crate. Automated scanner output is useful,
but reachability and impact help maintainers prioritize the fix.
