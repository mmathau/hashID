# Changelog

## [0.0.2] - 2023-12-11

### Added

- New `list` command to display information about supported hash types
- New hash type:
  - PFX .p12 Certificate type
  - ZipMonster type
  - Python Werkzeug SHA1 (HMAC-SHA1 (key = $salt))
  - Python Werkzeug SHA224 (HMAC-SHA224 (key = $salt))
  - Python Werkzeug SHA384 (HMAC-SHA384 (key = $salt))
  - Python Werkzeug SHA512 (HMAC-SHA512 (key = $salt))
  - Python Werkzeug scrypt (scrypt (key = $salt))
  - Python Werkzeug PBKDF2-HMAC-MD5 (key = $salt)
  - Python Werkzeug PBKDF2-HMAC-SHA1 (key = $salt)
  - Python Werkzeug PBKDF2-HMAC-SHA224 (key = $salt)
  - Python Werkzeug PBKDF2-HMAC-SHA384 (key = $salt)
  - Python Werkzeug PBKDF2-HMAC-SHA512 (key = $salt)
  - MSCHAPv2 C/R
  - DragonFly BSD $3$ w/ bug
  - DragonFly BSD $4$ w/ bug
  - DiskCryptor (PBKDF2-SHA512)
  - Cardano Encrypted 128-byte Secret Key (a.k.a XPrv)
  - RACF-KDFAES
  - Password Safe

### Fixed

- Fix various JtR formats
- Improve RIPEMD-128 regex
- Improve RIPEMD-160 regex
- Improve Keccak-256 regex
- Improve Keccak-512 regex
- Improve AIX {ssha256} regex
- Improve Python Werkzeug MD5 (HMAC-MD5 (key = $salt)) regex
- Improve Python Werkzeug SHA256 (HMAC-SHA256 (key = $salt)) regex
- Improve Python Werkzeug PBKDF2-HMAC-SHA256 (key = $salt) regex
- Improve Domain Cached Credentials 2 (DCC2), MS Cache 2 regex
- Improve Domain Cached Credentials (DCC), MS Cache regex
- Improve LastPass + LastPass sniffed regex
- Improve MS-AzureSync PBKDF2-HMAC-SHA256 regex
- Improve MyBB 1.2+, IPB2+ (Invision Power Board) regex
- Improve Apple iWork regex
- Improve 1Password(Agile Keychain) regex

### Changed

- Refactored all CLI commands using `urfave/cli/v3s`
- Upgrade dependencies

### Removed

## [0.0.1] - 2023-11-28

- Initial release

[0.0.2]: https://git.ntwrk.space/mmaths/hashID/compare/v0.0.1...v0.0.2
[0.0.1]: https://git.ntwrk.space/mmaths/hashID/releases/tag/v0.0.1
