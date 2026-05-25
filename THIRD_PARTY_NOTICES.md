# Third-party Notices

Traversio includes small C support code under `Sources/TraversioCCrypto`.

The following source files preserve original notices in place:

- `Sources/TraversioCCrypto/blf.h`
- `Sources/TraversioCCrypto/blowfish.c`
- `Sources/TraversioCCrypto/bcrypt_pbkdf.c`
- `Sources/TraversioCCrypto/umac.c`
- `Sources/TraversioCCrypto/umac.h`
- `Sources/TraversioCCrypto/umac128.c`
- `Sources/TraversioCCrypto/chachapoly.c`

Those files include code adapted from OpenBSD, OpenSSH, and Ted Krovetz's UMAC implementation. Keep the original notices when modifying or redistributing these files.

`Tests/TraversioTests/Support/OpenSSHTestFixtures.swift` contains small OpenSSH regress test fixtures used to validate host-certificate parsing and verification behavior.
