# Security Policy

Traversio is an SSH client library, so security reports should be handled carefully.

## Reporting

Report security issues privately through the repository owner's security contact channel. Avoid filing public issues for exploitable authentication, host-trust, parsing, crypto, memory-safety, or denial-of-service findings.

Include:

- affected version or commit
- platform and Swift toolchain version
- minimal reproduction details
- packet transcript or fixture when relevant
- expected and observed behavior

## Supported Version

The first public support boundary starts at `1.0.0`.

## Security-Sensitive Areas

The most sensitive code paths are:

- host-key verification and trust policy
- authentication
- binary packet parsing and serialization
- key exchange, encryption, MAC, compression, and rekey behavior
- channel and forwarding lifecycle
- cancellation and cleanup after transport failure

Changes in these areas should include focused tests and conservative failure behavior.
