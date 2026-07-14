# False-Positive Patterns: java-weak-cryptography

- **language**: java
- **skill**: `java-weak-cryptography`
- **weakness**: `weak-cryptography`
- **dimension**: D7
- **source**: vuln_skill_builder `analysis/false-positive-patterns.yaml`

## Not a vulnerability

### `aes-gcm-unique-nonce`
- Pattern: AES/GCM with SecureRandom nonce per message and managed key
- Reason: strong AEAD usage

### `securerandom-default`
- Pattern: SecureRandom without static seed for tokens/keys
- Reason: acceptable CSPRNG

### `bcrypt-argon2-password`
- Pattern: BCryptPasswordEncoder / Argon2 / SCrypt for passwords
- Reason: modern password hashing

### `md5-cache-key`
- Pattern: MD5 used only as non-security cache key or fingerprint with no trust boundary
- Reason: not a cryptographic security claim

### `sha256-file-integrity-with-signature`
- Pattern: SHA-256 checksum combined with separate signature/HMAC from trusted key
- Reason: integrity provided by signature, not hash alone

### `test-only-crypto`
- Pattern: weak crypto only under src/test or demo packages never shipped
- Reason: not production reachable

## Needs deeper review

### `aes-cbc`
- Pattern: AES/CBC without visible MAC
- Reason: may lack integrity; check Encrypt-then-MAC or protocol context

### `cipher-aes-default`
- Pattern: Cipher.getInstance("AES")
- Reason: often ECB default; confirm provider behavior

### `random-uuid`
- Pattern: UUID.randomUUID for session identifiers
- Reason: usually OK; verify if cryptographic unpredictability required

### `pbkdf2-params`
- Pattern: PBKDF2 present but iteration count unknown
- Reason: may be too low

### `custom-crypto-util`
- Pattern: CryptoUtil.encrypt wrapping JCA
- Reason: expand into real algorithm/IV/key handling

### `rsa-without-mode`
- Pattern: Cipher.getInstance("RSA")
- Reason: padding defaults vary; prefer explicit OAEP

### `spring-delegating-encoder`
- Pattern: DelegatingPasswordEncoder with legacy {MD5} ids
- Reason: verify default and encoding id for new passwords

