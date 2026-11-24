# bignum

Arbitrary-precision integers and constant-time arithmetic for the Goose
language, written in Goose: a foundation for cryptography.

- **`bignum`**: `BigInt`, signed integers of any size. Arithmetic,
  truncating and floor division, number theory, two's-complement bit
  operations, text in bases 2–36, and bytes. Variable-time, so never use it
  on secrets.
- **`bignum.ct`**: constant-time building blocks over fixed-width limb
  slices (masks, select, swap, compare, modular add/sub, small moduli,
  exact division).
- **`bignum.mont`**: constant-time Montgomery arithmetic for an odd modulus
  (multiply, exponentiate, reduce).
- **`bignum.x25519`**: X25519 Diffie-Hellman (RFC 7748), constant time.
- **`bignum.x448`**: X448 Diffie-Hellman (RFC 7748), constant time.
- **`bignum.ec`**: P-224, P-256, P-384, P-521, secp256k1 and
  brainpoolP256r1, P384r1 and P512r1 (RFC 5639): ECDH and deterministic
  ECDSA (RFC 6979), constant time.
- **`bignum.ed25519`**: Ed25519 signatures (RFC 8032), with Ed25519ctx and
  Ed25519ph; constant-time signing.
- **`bignum.ed448`**: Ed448 signatures (RFC 8032), with contexts and
  Ed448ph; constant-time signing.
- **`bignum.mlkem`**: ML-KEM-512/768/1024 (FIPS 203), post-quantum key
  encapsulation, constant time.
- **`bignum.mldsa`**: ML-DSA-44/65/87 (FIPS 204), post-quantum signatures,
  hedged or deterministic, with contexts and external mu; constant time.
- **`bignum.slhdsa`**: SLH-DSA (FIPS 205), stateless hash-based
  signatures, all twelve SHA2 and SHAKE sets, hedged or deterministic,
  with contexts, HashSLH-DSA and the internal interface.
- **`bignum.hpke`**: HPKE (RFC 9180), all four modes, with DHKEM over
  P-256/384/521 and X25519, ML-KEM and the ML-KEM hybrids (X-Wing among
  them), HKDF and SHAKE KDFs, AES-GCM, ChaCha20-Poly1305 and export-only.
- **`bignum.rsa`**: RSA (RFC 8017): key generation, PKCS #1 v1.5 and PSS
  signatures, OAEP and PKCS #1 v1.5 encryption; everything that touches a
  private key (the private operation, loading, generating) in constant
  time.
- **`bignum.dsa`**: DSA (FIPS 186-4), for legacy keys: parameters, keys,
  random-nonce and deterministic (RFC 6979) signatures; constant-time
  keys, nonces and signing.
- **`bignum.ffdh`**: finite-field Diffie-Hellman over RFC 3526's MODP
  groups 14, 15 and 16 (2048, 3072 and 4096 bits), as SSH uses them: keys,
  the peer value's range check, and the shared secret, the secret exponent
  raised in constant time. A secret exponent is at least 224 bits (NIST SP
  800-56A, RFC 7919 §5.2).
- **`bignum.aes`**: AES-128/192/256 and CTR mode, bitsliced, constant time.
- **`bignum.camellia`**: Camellia-128/192/256 (RFC 3713), constant time:
  its S-box runs as the AES one's bitsliced circuit between two affine maps.
- **`bignum.cmac`**: CMAC (SP 800-38B, RFC 4493) over any 8- or 16-byte
  block cipher here: AES-CMAC, Camellia-CMAC; constant time when the
  cipher is.
- **`bignum.gcm`**: AES-GCM authenticated encryption, constant time.
- **`bignum.ccm`**: AES-CCM (SP 800-38C, RFC 3610), SMB 3's cipher,
  constant time.
- **`bignum.keywrap`**: AES Key Wrap (RFC 3394, SP 800-38F KW) and with
  padding (RFC 5649, KWP), constant time; JOSE's A*KW uses it.
- **`bignum.shamir`**: secret sharing as KMIP's Split Keys do it: XOR, and
  Shamir's polynomial sharing in GF(2^8), GF(2^16) and a prime field,
  constant time in the secret and the parts.
- **`bignum.modes`**: CBC, CFB, OFB and CTR over any of the block ciphers,
  XTS over 16-byte ones, and PKCS #7 padding.
- **`bignum.des`**: DES and triple DES, for legacy data.
- **`bignum.rc4`**: RC4, for legacy protocols only.
- **`bignum.blowfish`**, **`bignum.cast5`**, **`bignum.twofish`**,
  **`bignum.tea`** (TEA and XTEA), **`bignum.rc2`**: the legacy block
  ciphers of Go's x/crypto (and RC2 from its PKCS #12 decoder), each
  usable with `bignum.modes`. Table-driven, so not constant time.
- **`bignum.salsa20`**: Salsa20, XSalsa20 and HSalsa20.
- **`bignum.nacl`**: NaCl secretbox, box (and sealed anonymous boxes),
  sign and auth, as Go's x/crypto/nacl.
- **`bignum.chacha20`**: ChaCha20, Poly1305 and ChaCha20-Poly1305 (RFC 8439),
  and XChaCha20-Poly1305.
- **`bignum.sha256`**: SHA-256, SHA-224 and MGF1.
- **`bignum.sha512`**: SHA-512, SHA-384, SHA-512/224 and SHA-512/256.
- **`bignum.sha1`**: SHA-1, for what still needs it.
- **`bignum.sha3`**: SHA3-224/256/384/512, SHAKE128/256 and cSHAKE.
- **`bignum.kmac`**: KMAC128 and KMAC256 (NIST SP 800-185), the keyed MAC
  over cSHAKE; OpenPGP's post-quantum key combiner uses it.
- **`bignum.md4`**, **`bignum.ripemd160`**: MD4 and RIPEMD-160, for the
  formats that still carry them.
- **`bignum.md5`**: MD5, for what still needs it.
- **`bignum.blake2`**: BLAKE2b and BLAKE2s, keyed or not, and the BLAKE2Xb and
  BLAKE2Xs XOFs.
- **`bignum.hmac`**: one-shot hashing, HMAC, HKDF and MGF1 over any of them.
- **`bignum.kdf`**: PBKDF2 and scrypt.
- **`bignum.bcrypt`**: bcrypt password hashes, as Go's x/crypto/bcrypt, and
  bcrypt_pbkdf (OpenBSD's KDF for OpenSSH's encrypted keys).
- **`bignum.argon2`**: Argon2id, Argon2i and Argon2d (RFC 9106).
- Random bytes for keys come from the `entropy` package (`entropy::random_bytes`:
  getentropy, or BCryptGenRandom on Windows), which bignum imports by name
  only, so a program can declare another package of that name in its root.

```goose
import std;
import bignum from "SorinS/bigmongoose@v0.9.1";
import entropy from "SorinS/entropygoose@v0.9.1";   // bignum needs it; the root declares it

fn main() {
    let a, ok = bignum::parse("123456789012345678901234567890");
    let b = bignum::pow(bignum::big(2), 100);
    print(bignum::mul(a, b));                       // print/str/format render in decimal
    let q, r = bignum::divmod_floor(a, bignum::big(-97));
    print(q, " ", r, " ", bignum::to_hex(b));
}
```

```goose
import bignum from "SorinS/bigmongoose@v0.9.1";
import entropy from "SorinS/entropygoose@v0.9.1";   // bignum needs it; the root declares it
import bignum.x25519;

let sk, pk = bignum::x25519_keypair();
let secret, ok = bignum::x25519_shared(sk, peer_pk);   // ok is false for a low-order peer
```

```goose
import bignum from "SorinS/bigmongoose@v0.9.1";
import entropy from "SorinS/entropygoose@v0.9.1";   // bignum needs it; the root declares it
import bignum.rsa;
import bignum.gcm;

let key = bignum::rsa_generate(2048);
let pub = bignum::rsa_public(key);
let sig, signed = bignum::rsa_sign_pss(key, msg);
let good = bignum::rsa_verify_pss(pub, msg, sig);
let ct = bignum::rsa_encrypt_oaep(pub, secret);
let pt, ok = bignum::rsa_decrypt_oaep(key, ct);

let sealed = bignum::aes_gcm_seal(key32, nonce12, aad, plaintext);   // ciphertext || tag
let opened, ok2 = bignum::aes_gcm_open(key32, nonce12, aad, sealed);  // ok2 false if tampered
```

```goose
import bignum from "SorinS/bigmongoose@v0.9.1";
import entropy from "SorinS/entropygoose@v0.9.1";   // bignum needs it; the root declares it
import bignum.ec;
import bignum.ed25519;
import bignum.hmac;

let c = bignum::p256();                                  // or bignum::p384()
let sk, pk = bignum::ec_keypair(c);                      // pk is 04 || x || y
let shared, ok = bignum::ecdh_shared(c, sk, peer_pk);    // ok false for an invalid point
let sig = bignum::ecdsa_sign(c, sk, msg);                // r || s; ecdsa_sig_to_der for TLS
let good = bignum::ecdsa_verify(c, pk, msg, sig);

let seed, edpk = bignum::ed25519_keypair();
let edsig = bignum::ed25519_sign(seed, msg);
let edgood = bignum::ed25519_verify(edpk, msg, edsig);

let okm = bignum::hkdf(256, salt, shared, info, 32);    // or 384, 512
```

## Layer 1: `BigInt`

`struct BigInt { neg: bool, mag: u32[>..] }` is a sign and 32-bit limbs,
least significant first, always normalized: no leading zero limbs, and zero
is never negative. Limb products are taken in `u64`.

| Group | Functions |
|---|---|
| Make and convert | `zero` `one` `big(i64)` `from_u64` `to_i64 -> i64, bool` `to_u64` `to_f64` |
| Inspect | `is_zero` `is_neg` `is_odd` `is_even` `sign` `bit_len` `test_bit` |
| Compare | `cmp` `eq` `ne` `lt` `le` `gt` `ge` `cmp_i64` |
| Arithmetic | `add` `sub` `mul` `sqr` `neg` `abs` `pow(a, u64)` |
| Division | `divmod` `div` `rem` (truncating, like C); `divmod_floor` `div_floor` `mod_floor` (floor, like Python); zero divisor aborts |
| Number theory | `gcd` `lcm` `ext_gcd -> g, x, y` `modinv -> inv, bool` `modpow` `isqrt` |
| Bits | `shl` `shr` `bit_and` `bit_or` `bit_xor` `bit_not`; negatives as infinite two's complement, so `shr` rounds down |
| Text | `parse(s, base = 10) -> BigInt, bool` (sign, `0x` in base 16), `to_str(a, base = 10)`, `to_hex`, `format_base(out, a, base)` |
| Bytes | `from_bytes_be/le`, `to_bytes_be/le(a, width)` |
| In place | `add_to` `sub_from` `add_i64_to` `mul_to` `mod_to` `mul_add_small_to` `div_small_to` |

Multiplication is schoolbook below `KARATSUBA_MIN` (40) limbs and Karatsuba
above it, with unbalanced operands split into chunks. Squaring (`sqr`, and
`mul` of two equal values) computes each cross product once, about half
the limb products, with Karatsuba's three half-size squarings above the
threshold. Division is Knuth's Algorithm D. `modpow` slides a window of up
to 6 bits over the exponent; with an odd modulus each step is a Montgomery
product or square, with an even one a product and a division. `to_str` and
`parse` split numbers above 40 limbs (1,600 digits) in halves at powers of
10^9 (base^k in other bases). `parse` then costs Karatsuba products, below
quadratic; `to_str` costs Algorithm D divisions, still quadratic but with
multiply-adds where the chunk-by-chunk loop took a hardware division per
limb per nine digits.

**Goose specifics worth knowing:**

- Goose has no operator overloading, so the arithmetic is named functions.
- Parameters are untyped (generic), so a variable *or* a temporary binds
  by reference: `add(mul(a, b), c)` copies nothing, and the results are
  built in place at their destination.
- `x = add(x, y)` is a compile error: the new value would be built over its
  own input. Use `add_to(x, y)`, or `let t = add(x, y); x = copy(t);`.
- A `BigInt` is resizable, so it cannot be an array element and `==` does
  not apply. Use `eq`, and keep collections as limb arrays (see
  `examples/factorial.goose`).

## Layer 2: constant time

`bignum.x25519` keeps a field element in ten signed limbs, radix 2^25.5 as
in ref10, with unrolled multiply and square. The Montgomery ladder makes
255 fixed steps and swaps with masks. At the generated-C level, the field
ops, the ladder swap and `ct_eq_bytes` have no branches on secret data; the
only branches are on lengths and public counters. One X25519 takes about
85 µs in a native build (Apple Silicon, clang -O2).

`bignum.ct` holds masks, `ct_select`, `ct_cswap`, `ct_eq`, `ct_lt`,
`ct_is_zero`/`ct_is_one`, `ct_add`/`ct_sub` with carry out and their masked
forms, `ct_shr1`, `ct_cond_sub`, `ct_mod_add`/`ct_mod_sub`, `ct_mod_small` (a
number mod a public d < 2^16 by multiplying, since a division instruction's
time can follow its operands) and `ct_div_exact` (by a public odd e that
divides exactly, by multiplying with 1/e mod 2^32), all over `u32[:]` of a
public length. `bignum.mont` builds on them: `mont_mul` (CIOS), `mont_r2`
(R² mod m by doubling, so no division by a secret modulus), `ct_reduce` (a
wide number mod any m, a bit at a time), `ct_mul`, `mont_modexp`, which
uses a 4-bit window over every bit of the exponent's width and reads its
table by scanning all 16 entries, and `ct_mod_inv` (1/a mod an odd m by
Möller's constant-time binary Euclid, GMP's `mpn_sec_invert`: 64 steps per
limb whatever the values).

Every other module may call `BigInt` only on public values, and
`scripts/ct_audit.py` (run by `run_tests.py`) holds the list of the
functions that do, each with its reason; a new call fails it until it is
looked at. Variable-time helpers outside `bignum.goose` end in `_vartime`,
as Go's do.

### RSA

| Group | Functions |
|---|---|
| Keys | `rsa_generate(bits, e = 65537)` (1024 to 8192, a multiple of 64; e odd, 3 to 2^31 − 1), `rsa_key_from(n, e, d, p, q) -> key, bool`, `rsa_key_from_bytes(n, e, d, p, q)` (big-endian, as PKCS #1 holds them), `rsa_public_from(n, e) -> pub, bool` (n 1024 to 8192 bits, Go's limit for TLS peers' keys; e odd, 3 to 2^31 − 1, as in Go), `rsa_public(key)`, `rsa_bits`, `rsa_size` |
| PKCS #1 v1.5 | `rsa_sign_pkcs1(key, msg, hash = 256) -> sig, bool`, `rsa_verify_pkcs1(pub, msg, sig, hash = 256)`; over a digest, `rsa_sign_pkcs1_digest(key, digest, hash = 256)` and `rsa_verify_pkcs1_digest(pub, digest, sig, hash = 256)` |
| PSS | `rsa_sign_pss(key, msg, salt_len = -1, hash = 256) -> sig, bool`, `rsa_sign_pss_with_salt(key, msg, salt, hash = 256) -> sig, bool`, `rsa_verify_pss(pub, msg, sig, salt_len = -1, hash = 256)`; a salt_len of -1 means the hash's length; over a digest, `rsa_sign_pss_digest(key, digest, salt_len = -1, hash = 256)`, `rsa_sign_pss_digest_with_salt` and `rsa_verify_pss_digest(pub, digest, sig, salt_len = -1, hash = 256)` |
| OAEP | `rsa_encrypt_oaep(pub, msg, label = "", hash = 256, mgf = 0)`, `rsa_encrypt_oaep_with_seed`, `rsa_decrypt_oaep(key, ct, label = "", hash = 256, mgf = 0) -> msg, bool`, `rsa_oaep_max(key, hash = 256)`; `mgf` names MGF1's hash when it is not the label's (Go's OAEPOptions.MGFHash) |
| PKCS #1 v1.5 encryption | `rsa_encrypt_pkcs1(pub, msg)`, `rsa_decrypt_pkcs1(key, ct) -> msg, bool`, `rsa_decrypt_pkcs1_session_key(key, ct, key_out) -> bool` |
| Raw | `rsa_public_op(pub, x)`, `rsa_private_op(key, x) -> bytes, bool` |

`hash` is any of bignum.hmac's hash ids (SHA-256 by default), and PSS
runs MGF1 on the same hash; OAEP does too unless `mgf` names another. A key is fixed-size limb
arrays (`u32[..256]`, so at most 8192 bits), and every function that only
needs the public half accepts a private key as well. The private operation
works by CRT. It blinds its input with r^e for a random r (r and 1/r drawn
and computed in constant time), and checks the result against the public
exponent before releasing it, so a fault in one CRT half cannot leak a
prime. A result that fails the check is never released: signing then
returns false, as Go's returns an error (it also does for a key too small
for the hash, or a hash with no DigestInfo), and decryption folds the
check into its constant-time checks on the block, so a fault fails the
way a bad ciphertext does. Loading a key derives dp, dq and qinv (by
Fermat) and makes every check without branching on the numbers; only the
verdict is branched on. It then makes Go's checks that |p − q| >
2^(nbits/2 − 100) (Fermat's factoring) and d > 2^(nbits/2) (Wiener's and
Boneh-Durfee's attacks), and one private operation against the public key.
Key generation draws p = 3 mod 4 (so Miller-Rabin is one exponentiation
per round), divides by the small primes by multiplying, tests gcd(p − 1, e)
with `ct_mod_inv`, and takes d = 1/e mod (p − 1)(q − 1) through the public
e: with k = −1/φ mod e, d = (1 + kφ)/e. That is the RSA paper's d, as Go's
crypto/rsa had it before its FIPS module, which takes 1/e mod lcm(p − 1,
q − 1) in variable time instead. Only candidates that fail are branched on. PKCS #1 v1.5 signatures are verified by
rebuilding the encoding and comparing it whole. OAEP decryption checks
every field in constant time and reports one failure flag. PKCS #1 v1.5
decryption checks its padding in constant time too, but saying whether
it failed is a padding oracle (Bleichenbacher's attack). So, as in Go,
`rsa_decrypt_pkcs1_session_key` writes the key only when the padding is
good and the length right, and otherwise leaves the caller's random bytes
in place, with no difference in time or path. Use OAEP for anything new.

### DSA

`dsa_generate_parameters(l, n)` makes p, q, g for (1024, 160), (2048, 224),
(2048, 256) or (3072, 256) as Go's crypto/dsa does, and
`dsa_generate_key(p, q, g)` a key on them. `dsa_key_from(p, q, g, y, x =
"")` checks and holds big-endian parts (no x for a public key);
`dsa_public` drops x. `dsa_sign(key, digest)` uses a random nonce,
`dsa_sign_deterministic(key, digest, hash_id)` RFC 6979's, and
`dsa_verify(key, digest, sig)` checks an r ‖ s signature. Digests are cut
to q's leftmost bits, as FIPS 186 and openssl do; Go leaves that to the
caller. `dsa_sig_to_der` and `dsa_sig_from_der` convert to and from the
DER form that X.509 and openssl use. x and the nonces are drawn below q,
checked against it and used in constant time (a nonce's length leaking
over many signatures is enough to recover x, as the Minerva attacks
showed); only the public parameters go through `BigInt`.

### AES and GCM

`aes_init(key)` expands a 16-, 24- or 32-byte key. `aes_encrypt_block` and
`aes_decrypt_block` work on single blocks; `aes_ctr(k, iv, data)` is CTR
mode in place. The cipher is bitsliced, after BearSSL's `aes_ct`: eight
words hold two blocks, and the S-box is Boyar and Peralta's circuit, so no
table is indexed by data.

`aes_gcm_seal(key, nonce, aad, pt)` returns ciphertext and tag, and
`aes_gcm_open` returns the plaintext and whether the tag matched. On a
mismatch it returns nothing, and the in-place `gcm_decrypt` zeroes its
buffer. `gcm_init` / `gcm_encrypt` / `gcm_decrypt` keep the expanded key
for many messages. GHASH multiplies with integer multiplies on operands
spread into 4-bit lanes (as in BearSSL's `ghash_ctmul64`), not with tables.
Never reuse a nonce under one key. 12 bytes is the standard size; other
lengths work too. A message is at most `GCM_MAX` bytes ((2^32 − 2) · 16,
SP 800-38D): encrypting more aborts, as Go panics, and opening more fails;
`gcm_fits(n)` is the check all four use. Opening with a key of the wrong
length or an empty nonce returns false rather than aborting.

`aes_ccm_seal(key, nonce, aad, pt, tag_len)` and `aes_ccm_open` are CCM
the same way, and `ccm_encrypt` / `ccm_decrypt` work in place with an
expanded key. Nonces are 7 to 13 bytes and tags 4 to 16 (even); a message
must fit the counter the nonce leaves (`ccm_fits`): encrypting outside
those aborts, opening fails. A tag is checked at its full length, never as
a prefix.

`bignum.modes` has the other modes of Go's crypto/cipher, written once
over any block cipher with a `cipher_encrypt` overload (AES, Camellia, DES
and triple DES here). Each works in place from a one-block IV:
- `cbc_encrypt` and `cbc_decrypt` take whole blocks;
- `cfb_encrypt` and `cfb_decrypt` (full-block segments, CFB-128 for AES),
  `ofb_xor` and `ctr_xor` take any length.

`pkcs7_pad(data, bs = 16)` and `pkcs7_unpad(data, bs) -> data, bool` add
and remove CBC padding; unpadding checks in constant time. Without a MAC
checked first, a CBC decryption that reports bad padding is still a
padding oracle, so prefer an AEAD.

`camellia_init(key)` expands a 16-, 24- or 32-byte Camellia key (RFC
3713), with `camellia_encrypt_block` and `camellia_decrypt_block`, and
works with every mode. No table is indexed by data: Camellia's s1 is
A2(S(A1(x))) for the AES S-box S and two affine maps (A1 holds the
spec's 0xc5), so F's eight S-boxes are bignum.aes's bitsliced circuit on
eight bit planes, one byte a lane, with A1 and A2 as XORs of planes and
s2, s3, s4's bit rotations as masked moves between planes. The maps were
found by a linear-equivalence search, which `scripts/camellia_vectors.py`
repeats, and are checked on all 256 bytes against RFC 3713's SBOX1.

`cmac(k, msg)` is CMAC over any of these ciphers with 8- or 16-byte
blocks (a block of tag), and `cmac_verify(k, msg, tag)` compares a tag of
8 to a block's bytes (truncated CMACs are the leading bytes) in constant
time; a shorter tag is refused, as the tag's length comes with it.
`cmac_verify_len(k, msg, tag, tag_len)` takes the length from the caller
(1 to a block) and refuses a tag of any other length.

`des_init(key8)` and `des3_init(key24)` expand DES and triple-DES (EDE)
keys, with `des_encrypt_block` / `des3_encrypt_block` and their decrypt
forms. The S-boxes are bit masks selected by shifts, so no table is read
at a secret index. `rc4_init(key)` and `rc4_xor(r, data)` are RC4, which
is broken and, as in Go, indexes its state by secret values.


### AES Key Wrap

`aes_key_wrap(kek, key)` wraps a key of 16 bytes or more, a multiple of 8,
under a 16-, 24- or 32-byte AES key: 8 bytes longer. `aes_key_unwrap`
returns the key and true, or nothing and false. `aes_key_wrap_pad` and
`aes_key_unwrap_pad` are RFC 5649's form for keys of any length from one
byte. Unwrapping checks the integrity value (and KWP's length and zero
padding) under masks, so a wrong KEK and a changed byte fail alike and in
the same time. test/keywrap_vectors.goose holds RFC 3394 §4's and RFC
5649 §6's vectors.

### Secret sharing

`split_xor(secret, n, out)`, `split_gf8(secret, n, t, out)`,
`split_gf16(secret, n, t, out)` and `split_prime(secret, prime, n, t,
out)` write n parts one after another (part x, from 1, at (x - 1) times
a part's length); `join_xor(parts, len, out)`, `join_gf8(xs, parts, len,
out)`, `join_gf16` and `join_prime(xs, parts, prime, len, out)` give the
secret back from the parts numbered xs, at least t of them. The `_with`
forms take the random coefficients, for tests. The fields are KMIP 2.1
§13.1's: GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1 (0x11D, not AES's
0x11B), GF(2^16) as GF(2^8)[y] / (y^2 + y + 0x3A), and a prime (checked
by `prime_field_ok`) above every secret of the length; a part in the
prime field is an integer at the prime's width. Parts are 1 to 255 in
GF(2^8), to 65535 in GF(2^16). test/shamir_vectors.goose joins the OASIS
KMIP test cases' parts (TC-SJ-3, TC-SJ-4).
### ChaCha20-Poly1305

`chacha20_poly1305_seal(key, nonce, aad, pt)` / `_open` and the in-place
`_encrypt` / `_decrypt`, with the same contract as GCM: 32-byte key,
12-byte nonce, 16-byte tag, nothing released on a bad tag; opening with a
key or nonce of the wrong length returns false. The pieces are
public too: `chacha20_block`, `chacha20_xor(key, counter, nonce, data)`,
and `poly1305` one-shot or streaming. A message is at most
`CHACHA20_POLY1305_MAX` bytes ((2^32 − 1) · 64, RFC 8439): encrypting more
aborts and opening more fails. `chacha20_xor` aborts, before touching the
data, if its 32-bit block counter would wrap; `chacha20_fits(counter, n)`
says whether it would. Poly1305 uses five 26-bit limbs
(after poly1305-donna-32), and its final reduction is a masked select.

`xchacha20_poly1305_seal` / `_open` (and `_encrypt` / `_decrypt`) take a
24-byte nonce, long enough to pick at random, as Go's
`chacha20poly1305.NewX`. They run ChaCha20-Poly1305 under a subkey from
`hchacha20(key, nonce[..16])`; `xchacha20_xor` is the bare stream.

### Elliptic curves

`bignum.ec` handles P-224, P-256, P-384, P-521, secp256k1 (SEC 2, a = 0)
and the Brainpool r1 curves brainpoolP256r1, P384r1 and P512r1 (RFC 5639,
as RFC 7027 and RFC 8734 use them in TLS) with one generic
implementation. `p224()`, `p256()`, `p384()`, `p521()`, `secp256k1()`,
`bp256()`, `bp384()` and `bp512()` return a `Curve`
holding the field prime, the group
order, their Montgomery constants, the coefficients, the generator and
three multiples of it for the comb below; build one and pass it to every
call. Field elements are limbs of the curve's width in Montgomery form.
Points are projective and added and doubled with the complete formulas of
Renes, Costello and Batina: their algorithms 4 and 6 for a = −3 (the NIST
curves), 1 and 3 for any a (Brainpool's and secp256k1's). Those have no
exceptional cases, so the point at infinity needs no branch. Scalar
multiplication and inversion run on fixed-size limb arrays, one copy of
the code for each curve width, so the C compiler unrolls them; P-521
reduces by folding at 2^521 instead of Montgomery's steps.

- k·P (ECDH): 4-bit windows across the whole scalar width, the table read
  by scanning every entry.
- k·G (keys, signatures): a comb with four teeth over 2^d G, 2^2d G and
  2^3d G (d a quarter of the width; `scripts/ec_comb_points.py` computes
  them), a quarter of the doublings, the table again read by scanning.
- u1·G + u2·Q (verification, public values): the comb interleaved with
  sliding windows over u2, in variable time.

| Group | Functions |
|---|---|
| Keys | `ec_keypair(c) -> sk, pk`, `ec_public_key(c, sk)`; private keys are `len` big-endian bytes (28, 32, 48, 64 or 66), public keys the uncompressed 04 ‖ x ‖ y |
| ECDH | `ecdh_shared(c, sk, peer) -> x, bool`: false unless the peer's point is on the curve and correctly encoded |
| ECDSA | `ecdsa_sign(c, sk, msg)`, `ecdsa_verify(c, pk, msg, sig)` with SHA-224 on P-224, SHA-256 on P-256 and brainpoolP256r1, SHA-384 on P-384 and brainpoolP384r1 and SHA-512 on P-521 and brainpoolP512r1; `ecdsa_sign_digest` and `ecdsa_verify_digest` for any hash |
| DER | `ecdsa_sig_to_der(raw)`, `ecdsa_sig_from_der(c, der) -> raw, bool` (strict: minimal integers, no trailing bytes) |
| Points | `ec_encode`/`ec_decode` (uncompressed, checked on the curve), `ec_encode_compressed`/`ec_decode_compressed` (SEC 1's 02/03 ‖ x; every curve but P-224, as their p is 3 mod 4), `ec_add`, `ec_neg`, `ec_mul` (krb5's SPAKE uses them) |

ECDSA nonces come from RFC 6979's HMAC-DRBG, so signing needs no
randomness and the same input always gives the same signature.

`bignum.ed25519` reuses X25519's field code. It uses extended coordinates
with the RFC's complete addition, and reduces scalars mod L through
`bignum.mont`. Functions: `ed25519_keypair() -> seed, pk`,
`ed25519_public(seed)`, `ed25519_sign(seed, msg)`,
`ed25519_verify(pk, msg, sig)`. Verification uses the cofactored equation
[8]SB = [8]R + [8]kA. It rejects S ≥ L and non-canonical encodings of A
and R. `ed25519_sign_ctx(seed, msg, ctx)` / `ed25519_verify_ctx` are
Ed25519ctx, with a context of 1 to 255 bytes. `ed25519_sign_ph(seed,
digest, ctx = "")` / `ed25519_verify_ph` are Ed25519ph. As in Go, they
take the message's SHA-512 digest, not the message.

`bignum.x448` and `bignum.ed448` are the same for Curve448. A field
element of GF(2^448 − 2^224 − 1) is sixteen signed limbs of 28 bits, so
every product and sum fits an i64 with no wider multiply, and reduction
folds the top half back with 2^448 ≡ 2^224 + 1. The multiply and square
are unrolled. `x448(scalar, u)` runs a ladder of 448 fixed steps;
`x448_base(scalar)`, `x448_keypair() -> sk, pk` and `x448_shared(sk,
peer) -> secret, bool` (false for an all-zero secret, from a low-order
peer) take and give 56 bytes. Ed448 uses projective coordinates with the
RFC's complete addition and doubling on the untwisted curve, and SHAKE256
throughout. Its keys are 57 bytes and its signatures 114:
`ed448_keypair() -> seed, pk`, `ed448_public(seed)`, `ed448_sign(seed,
msg, ctx = "")`, `ed448_verify(pk, msg, sig, ctx = "")`. Every Ed448
signature carries dom4, so a context of 0 to 255 bytes goes with plain
Ed448 too. `ed448_sign_ph(seed, digest, ctx = "")` / `ed448_verify_ph`
are Ed448ph, taking the 64-byte SHAKE256 digest from
`ed448_prehash(msg)`, as `ed25519_sign_ph` takes a SHA-512 digest.
Verification uses [4]SB = [4]R + [4]kA and rejects S ≥ L and
non-canonical encodings. In a native build (Apple M1, -O2) one X448 takes
about 460 µs, five times X25519, and an Ed448 signature or verification
about 1 ms, three times Ed25519.

### ML-KEM

`mlkem_keygen(k)` gives a 64-byte seed (the private key, as in Go's
crypto/mlkem) and the encapsulation key; k is 2, 3 or 4 for ML-KEM-512,
-768 or -1024. `mlkem_encaps(k, ek) -> secret, ct, ok` refuses a malformed
ek (wrong length, or a coefficient of q or more). `mlkem_decaps(k, seed,
ct) -> secret, ok` and `mlkem_decaps_dk(k, dk, ct)` decapsulate, from the
seed or from the expanded key, the second result of
`mlkem_keys_from_seed(k, seed) -> ek, dk`. A
ciphertext that does not re-encrypt to itself yields the implicit
rejection key J(z ‖ c), selected with a mask. `mlkem_encaps_with` takes
the message, for tests. Every reduction mod q, including Compress's
division, is a multiply and a shift (the KyberSlash class of timing leaks
cannot occur).

### ML-DSA

The set is 44, 65 or 87. `mldsa_keygen(set)` gives a 32-byte seed (the
private key, as in Go's crypto/mldsa) and the public key;
`mldsa_public_key(set, seed)` recomputes it, and `mldsa_expand_key` gives
the FIPS 204 expanded private key for formats that carry it.
`mldsa_sign(set, seed, msg, ctx = "")` is hedged (fresh randomness mixed
in) and `mldsa_sign_deterministic` is not; contexts run to 255 bytes.
`mldsa_verify(set, pk, msg, sig, ctx = "")` refuses wrong lengths and any
hint encoding but the canonical one. `mldsa_mu(pk, msg, ctx)`,
`mldsa_sign_mu` and `mldsa_verify_mu` work on a precomputed message
representative, as Go's `crypto.MLDSAMu` does. Products are Montgomery
reductions with masked corrections and Decompose is a multiply and shift,
so the secret side never divides or branches on secret values; the
rejection loop's restarts are public, as the standard allows.

### SLH-DSA

The set is one of `SLHDSA_SHA2_128S`, `SLHDSA_SHA2_128F`, ... up to
`SLHDSA_SHAKE_256F` (1 to 12, in the order of their OIDs, .20 to .31);
`slhdsa_name(set)` gives "SLH-DSA-SHA2-128s" and so on, and
`slhdsa_set_of_name` reads it back. `slhdsa_keygen(set)` gives the private
key (SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root, 4n bytes) and the public key
(PK.seed ‖ PK.root); `slhdsa_key_from_seed(set, seed)` makes them from the
3n-byte seed openssl and ACVP take, and `slhdsa_keygen_internal` from its
three parts. `slhdsa_public_key(set, sk)` is the key's tail, and
`slhdsa_check_key` recomputes PK.root (as costly as a key generation).
`slhdsa_sign(set, sk, msg, ctx = "")` is hedged (n fresh random bytes),
`slhdsa_sign_deterministic` is not, and `slhdsa_sign_with` takes the
randomness; contexts run to 255 bytes. `slhdsa_verify(set, pk, msg, sig,
ctx = "")` refuses wrong lengths. HashSLH-DSA is `slhdsa_hash_sign(set, sk,
msg, ph, ctx = "")` (and `_deterministic`, `_with`) and
`slhdsa_hash_verify`, with `ph` one of hmac's `HASH_*` numbers for SHA-224
to SHA-512, SHA-512/224, SHA-512/256 and SHA3-224 to SHA3-512, or
`SLHDSA_PH_SHAKE128` / `SLHDSA_PH_SHAKE256`. `slhdsa_sign_internal` and
`slhdsa_verify_internal` take the prepared message M', as ACVP's internal
interface does.

| Set | n | public key | signature | keygen | sign | verify |
|---|---|---|---|---|---|---|
| SHA2-128s | 16 | 32 | 7856 | 0.29 s | 2.3 s | 2 ms |
| SHA2-128f | 16 | 32 | 17088 | 4 ms | 0.10 s | 6 ms |
| SHA2-192s | 24 | 48 | 16224 | 0.47 s | 4.7 s | 4 ms |
| SHA2-192f | 24 | 48 | 35664 | 7 ms | 0.20 s | 11 ms |
| SHA2-256s | 32 | 64 | 29792 | 0.33 s | 4.3 s | 6 ms |
| SHA2-256f | 32 | 64 | 49856 | 20 ms | 0.44 s | 12 ms |
| SHAKE-128s | 16 | 32 | 7856 | 0.33 s | 2.5 s | 3 ms |
| SHAKE-128f | 16 | 32 | 17088 | 5 ms | 0.12 s | 7 ms |
| SHAKE-192s | 24 | 48 | 16224 | 0.54 s | 4.8 s | 4 ms |
| SHAKE-192f | 24 | 48 | 35664 | 8 ms | 0.21 s | 12 ms |
| SHAKE-256s | 32 | 64 | 29792 | 0.38 s | 4.5 s | 7 ms |
| SHAKE-256f | 32 | 64 | 49856 | 24 ms | 0.57 s | 14 ms |

(Under the JIT at -O2 on an Apple M-series machine; openssl is several
times faster.) The "s" sets are slow by design, so the module spends its
effort on the hashes: each tweakable hash is one compression, with SHA2's
PK.seed block hashed once per key and its midstate kept, SHAKE's inputs
absorbed a lane at a time, and Keccak-f and the SHA-256 and SHA-512
compressions in local variables (unrolled), three to ten times faster than
the general ones in `sha3`, `sha256` and `sha512`. Each XMSS and FORS tree
is built once per signature, giving its root, the authentication path and
the WOTS+ signature together. Secrets (SK.seed, SK.prf) only enter hashes;
the tree and leaf indices, FORS indices and WOTS+ digits that the code
branches on or indexes by are all in the signature.

### HPKE

Algorithms are named by their RFC 9180 and draft-ietf-hpke-pq ids
(`HPKE_DHKEM_X25519`, `HPKE_MLKEM768_X25519`, `HPKE_HKDF_SHA256`,
`HPKE_SHAKE256`, `HPKE_AES128GCM`, `HPKE_EXPORT_ONLY`, ...), the same set
as Go's crypto/hpke plus ML-KEM-512. `hpke_keygen(kem)` and
`hpke_derive_key_pair(kem, ikm)` give a private key in the KEM's own
serialization and the public key. `hpke_sender(kem, kdf, aead, pk, info,
psk = "", psk_id = "", sk_s = "") -> enc, ctx, ok` and `hpke_recipient(kem,
kdf, aead, sk, enc, info, psk, psk_id, pk_s)` set up a context; a PSK
selects the PSK modes and a sender key the authenticated ones (DHKEM
only; the SHAKE KDFs, as in Go, run in base mode only). Then
`hpke_seal(ctx, aad, pt)`, `hpke_open` (which leaves the sequence number
alone on failure) and `hpke_export(ctx, exporter_context, n) -> bytes, ok`
(false for n above HKDF's 255 * Nh, or 65535 for a SHAKE KDF). With a
SHAKE KDF, an info, PSK or PSK id of 64 KiB or more is refused, as its
length prefix is 16 bits.
`hpke_seal_once` and `hpke_open_once` are Go's single-shot `Seal` and
`Open`: the encapsulated key followed by the ciphertext.

### Hashes, HMAC, HKDF

Every hash comes one-shot or streaming (`*_init`, `*_update`, `*_final`):
- `sha1`;
- `sha224` and `sha256`;
- `sha384`, `sha512`, `sha512_224` and `sha512_256`;
- `sha3(bits, data)`, and `shake(bits, data, n)` with `shake_read` to
  squeeze any amount;
- `cshake(bits, name, custom, data, n)` and `cshake_init`, as Go's
  `sha3.NewCSHAKE128/256`;
- `md5`;
- `blake2b(data, outlen = 64, key = "")` and `blake2s(data, outlen = 32,
  key = "")`, keyed when a key is given;
- `blake2xb(data, n, key = "")` and `blake2xs`, BLAKE2X as Go's
  `blake2b.NewXOF` and `blake2s.NewXOF`. The output length n is part of
  the hash. To stream, use `blake2xb_init(n, key)`, `blake2xb_update`,
  then `blake2xb_read(x, out) -> count` as often as needed. n = 0 means an
  unknown length, read up to 256 GiB (BLAKE2Xb) or 128 GiB (BLAKE2Xs).

The generic functions name a hash by an id: 128 (MD5), 160 (SHA-1), 224, 256, 384,
512, `HASH_SHA512_224`, `HASH_SHA512_256`, `HASH_SHA3_224` through
`HASH_SHA3_512`, and `HASH_BLAKE2B_256`, `_384`, `_512` and
`HASH_BLAKE2S_256` (Go's `crypto.BLAKE2b_256` and so on). They include
`hash_bits(id, data)`, HMAC, HKDF, PBKDF2, MGF1, RSA PSS and OAEP, and
ECDSA over a digest (`ecdsa_sign_digest`). RSA PKCS #1 v1.5 signatures
take MD5, SHA-1, SHA-2 and SHA-3 but not BLAKE2, which has no DigestInfo
(as in Go); verifying with an unsupported hash returns false. `hmac(id, key, msg)` and the `hmac_sha256/384/512` shortcuts cover HMAC. `hmac_prefix_ct(id, key,
prefix, data, len, min_len)` is HMAC-SHA-1 or -SHA-256 of prefix ‖
data[..len] in time that depends on neither len nor the bytes, only on the
public lengths, for TLS's CBC records (Lucky13), as OpenSSL's
`ssl3_cbc_digest_record`. It takes prefix and data up to
`HMAC_PREFIX_CT_MAX` (2^30 bytes) together, checked by
`hmac_prefix_ct_fits`, since it compares positions as 32-bit numbers.
`hkdf_extract`, `hkdf_expand` and `hkdf` cover HKDF. TLS 1.3's HKDF-Expand-Label is a
few lines on top of `hkdf_expand` and is not included.

### Go's x/crypto extras

- `md4(data)`, `ripemd160(data)`, each also streaming (`_init`,
  `_update`, `_final`).
- `salsa20_xor(key, nonce, data)`: Salsa20 for an 8-byte nonce, XSalsa20
  for a 24-byte one, in place; `hsalsa20(key, input16)`.
- NaCl: `secretbox_seal(msg, nonce, key)` (tag first, as NaCl) and
  `secretbox_open` (false, not an abort, for a key or nonce of the wrong
  length, as `box_open` for keys); `box_keypair`, `box_precompute`, `box_seal(msg, nonce,
  peer_pk, sk)`, `box_open`, `box_seal_anonymous(msg, pk)` and
  `box_open_anonymous(sealed, pk, sk)`; `nacl_sign(msg, sk64)` and
  `nacl_sign_open`; `nacl_auth(msg, key)` and `nacl_auth_verify`.
- `bcrypt_hash(password, cost = 10) -> hash, ok` ("$2a$", false past 72
  bytes or for a cost above 31), `bcrypt_verify(hash, password)` (in
  constant time; $2b$ and $2y$ too; false for a password past 72 bytes,
  whose tail bcrypt would never read) and `bcrypt_cost(hash)`;
  `bcrypt_pbkdf(password, salt, rounds, key_len) -> key, ok` (false for
  an empty password or salt, rounds below 1 or a key over 1024 bytes).
- `blowfish_init(key)`, `cast5_init(key16)`, `twofish_init(key)`,
  `tea_init(key, rounds = 64)`, `xtea_init(key)`, `rc2_init(key,
  effective_bits)`, each with `_encrypt_block` / `_decrypt_block` and
  usable with every mode.
- `xts_encrypt(k1, k2, sector, data)` and `xts_decrypt`, whole 16-byte
  blocks, as Go's x/crypto/xts.

### Password hashing and key derivation

| Function | Parameters |
|---|---|
| `argon2id_key(password, salt, t, m, p, len)` | Go's `argon2.IDKey`: t passes over m KiB with p lanes. The one to use for passwords. |
| `argon2i_key(...)` | Go's `argon2.Key` (Argon2i) |
| `argon2(kind, password, salt, secret, ad, t, m, p, len)` | `ARGON2D`, `ARGON2I` or `ARGON2ID`, with the optional secret key and associated data |
| `scrypt(password, salt, n, r, p, len) -> key, bool` | as `scrypt.Key`; false for bad parameters (n above 2^32 among them) |
| `pbkdf2(hash, password, salt, iter, len)` | over HMAC with any hash id, as `crypto/pbkdf2` |

The lanes of Argon2 are filled one after another, which gives the same
output as running them in parallel. Argon2i, and Argon2id in the first
half of its first pass, read memory at positions that do not depend on
the password. Argon2d, Argon2id after that, and scrypt read at
password-dependent positions, as their designs intend.

### Speed

Side by side with OpenSSL 3.6.4 on an Apple M1: the Goose figures from a
native build (clang -O2), openssl's from `openssl speed -evp` over 16 KiB
buffers, PBKDF2 and scrypt through Python's hashlib (which calls OpenSSL),
and Argon2id through `openssl kdf` less its start-up time. The last column
is Goose / OpenSSL: above 1 is faster. `python3 scripts/speed_vs_openssl.py
[prefix]` rebuilds `examples/speed.goose` and prints this table afresh.

| Operation | Goose | OpenSSL 3.6.4 | Goose / OpenSSL |
|---|---:|---:|---:|
| md5 | 275.4 MB/s | 696.8 MB/s | 0.40 |
| sha1 | 240.0 MB/s | 2,394.3 MB/s | 0.10 |
| sha256 | 209.4 MB/s | 2,441.7 MB/s | 0.09 |
| sha512 | 306.3 MB/s | 1,430.4 MB/s | 0.21 |
| sha3-256 | 210.2 MB/s | 900.3 MB/s | 0.23 |
| blake2b512 | 595.0 MB/s | 746.0 MB/s | 0.80 |
| blake2s256 | 448.0 MB/s | 441.9 MB/s | 1.01 |
| hmac-sha256 | 206.7 MB/s | 2,451.3 MB/s | 0.08 |
| aes-128-gcm | 81.4 MB/s | 8,107.2 MB/s | 0.01 |
| aes-256-gcm | 61.6 MB/s | 6,791.0 MB/s | 0.01 |
| chacha20-poly1305 | 388.8 MB/s | 1,824.9 MB/s | 0.21 |
| chacha20 | 520.5 MB/s | 2,523.0 MB/s | 0.21 |
| aes-128-ctr | 88.8 MB/s | 12,823.0 MB/s | 0.01 |
| aes-256-ctr | 67.2 MB/s | 9,513.4 MB/s | 0.01 |
| aes-128-cbc | 48.2 MB/s | 1,594.9 MB/s | 0.03 |
| aes-256-cbc | 34.9 MB/s | 1,128.9 MB/s | 0.03 |
| aes-128-cfb | 47.8 MB/s | 1,105.4 MB/s | 0.04 |
| aes-128-ofb | 48.6 MB/s | 1,178.5 MB/s | 0.04 |
| des-cbc | 9.7 MB/s | 87.4 MB/s | 0.11 |
| des-ede3-cbc | 3.3 MB/s | 33.5 MB/s | 0.10 |
| rc4 | 1,063.0 MB/s | 1,281.6 MB/s | 0.83 |
| x25519 | 11,347 op/s | 33,683 op/s | 0.34 |
| ed25519-sign | 3,626 op/s | 33,561 op/s | 0.11 |
| ed25519-verify | 3,389 op/s | 11,904 op/s | 0.28 |
| ecdh-p224 | 3,634 op/s | 21,369 op/s | 0.17 |
| ecdsa-p224-sign | 6,394 op/s | 30,325 op/s | 0.21 |
| ecdsa-p224-verify | 2,962 op/s | 13,828 op/s | 0.21 |
| ecdh-p256 | 2,666 op/s | 25,301 op/s | 0.11 |
| ecdsa-p256-sign | 4,788 op/s | 59,173 op/s | 0.08 |
| ecdsa-p256-verify | 2,201 op/s | 19,034 op/s | 0.12 |
| ecdh-p384 | 835 op/s | 4,765 op/s | 0.18 |
| ecdsa-p384-sign | 1,626 op/s | 7,217 op/s | 0.23 |
| ecdsa-p384-verify | 699 op/s | 3,319 op/s | 0.21 |
| ecdh-p521 | 406 op/s | 4,725 op/s | 0.09 |
| ecdsa-p521-sign | 729 op/s | 4,799 op/s | 0.15 |
| ecdsa-p521-verify | 333 op/s | 2,658 op/s | 0.13 |
| rsa2048-sign | 113 op/s | 1,856 op/s | 0.06 |
| rsa2048-verify | 7,479 op/s | 72,060 op/s | 0.10 |
| rsa3072-sign | 39.9 op/s | 637.6 op/s | 0.06 |
| rsa3072-verify | 3,139 op/s | 33,629 op/s | 0.09 |
| rsa4096-sign | 16.7 op/s | 290.1 op/s | 0.06 |
| rsa4096-verify | 1,753 op/s | 19,562 op/s | 0.09 |
| mlkem512-keygen | 39,705 op/s | 46,748 op/s | 0.85 |
| mlkem512-encaps | 33,467 op/s | 63,322 op/s | 0.53 |
| mlkem512-decaps | 26,525 op/s | 39,648 op/s | 0.67 |
| mlkem768-keygen | 24,578 op/s | 28,965 op/s | 0.85 |
| mlkem768-encaps | 20,870 op/s | 44,222 op/s | 0.47 |
| mlkem768-decaps | 16,854 op/s | 27,930 op/s | 0.60 |
| mlkem1024-keygen | 15,768 op/s | 19,476 op/s | 0.81 |
| mlkem1024-encaps | 13,934 op/s | 27,766 op/s | 0.50 |
| mlkem1024-decaps | 11,510 op/s | 20,919 op/s | 0.55 |
| pbkdf2-sha256-100k | 14.1 op/s | 90.1 op/s | 0.16 |
| scrypt-n15-r8 | 17.3 op/s | 14.7 op/s | 1.18 |
| argon2id-t1-64m-p4 | 32.6 op/s | 25.1 op/s | 1.30 |

Where OpenSSL is far ahead it is mostly hardware: on this CPU it uses the
AES, PMULL (GHASH) and SHA-1/SHA-2/SHA-3 instructions, and 64-bit-limb
assembly with a 64x64->128 multiply for the curves and RSA. Goose has no
intrinsics and no wide multiply, so this library runs table-free,
constant-time AES and 32-bit limbs. OpenSSL's ML-KEM also keeps the
expanded matrix with the key, which encapsulation and decapsulation here
rebuild each time. Where neither side has special instructions (BLAKE2,
RC4, scrypt, Argon2) the two are even or Goose is ahead. RSA-2048 key
generation takes about 0.27 s on average (ten runs, in constant time).

Against Rust, on the same machine: `python3 scripts/speed_vs_rust.py
[prefix]` builds `tools/rustbench`, the same operations on the same inputs
with the RustCrypto crates (dalek for X25519 and Ed25519; Rust 1.98.1,
release, LTO), twice. The first build has the CPU's crypto instructions
turned off (`aes_force_soft` and the like), as the Goose code has none; it
is the comparison of compiled code with compiled code. The second has
them all on. On Apple silicon these crate versions use AES, PMULL, NEON
and the SHA-2 instructions only when asked (`--cfg aes_armv8` and the
like; the script asks), so a plain `cargo build` gets about the first
column there. On x86 they find AES-NI, CLMUL and SHA-NI at run time.

| Operation | Goose | Rust, software | Rust, CPU instructions | Goose / software | Goose / CPU |
|---|---:|---:|---:|---:|---:|
| md5 | 274.2 MB/s | 628.7 MB/s | 630.6 MB/s | 0.44 | 0.43 |
| sha1 | 236.1 MB/s | 989.3 MB/s | 989.2 MB/s | 0.24 | 0.24 |
| sha256 | 209.3 MB/s | 354.2 MB/s | 2,180.3 MB/s | 0.59 | 0.10 |
| sha512 | 303.7 MB/s | 554.1 MB/s | 1,434.6 MB/s | 0.55 | 0.21 |
| sha3-256 | 209.9 MB/s | 614.7 MB/s | 615.0 MB/s | 0.34 | 0.34 |
| blake2b512 | 594.9 MB/s | 1,042.9 MB/s | 1,066.6 MB/s | 0.57 | 0.56 |
| blake2s256 | 448.9 MB/s | 623.9 MB/s | 633.0 MB/s | 0.72 | 0.71 |
| hmac-sha256 | 206.2 MB/s | 343.3 MB/s | 2,089.6 MB/s | 0.60 | 0.10 |
| aes-128-gcm | 81.4 MB/s | 174.7 MB/s | 1,922.7 MB/s | 0.47 | 0.04 |
| aes-256-gcm | 61.5 MB/s | 140.4 MB/s | 1,837.8 MB/s | 0.44 | 0.03 |
| chacha20-poly1305 | 389.8 MB/s | 459.1 MB/s | 679.5 MB/s | 0.85 | 0.57 |
| chacha20 | 529.1 MB/s | 675.4 MB/s | 1,260.1 MB/s | 0.78 | 0.42 |
| aes-128-ctr | 91.6 MB/s | 249.7 MB/s | 8,427.0 MB/s | 0.37 | 0.01 |
| aes-256-ctr | 67.2 MB/s | 186.1 MB/s | 6,604.9 MB/s | 0.36 | 0.01 |
| aes-128-cbc | 48.3 MB/s | 60.9 MB/s | 1,404.8 MB/s | 0.79 | 0.03 |
| aes-256-cbc | 34.8 MB/s | 46.5 MB/s | 900.9 MB/s | 0.75 | 0.04 |
| aes-128-cfb | 48.0 MB/s | 62.0 MB/s | 1,507.8 MB/s | 0.77 | 0.03 |
| aes-128-ofb | 48.4 MB/s | 61.6 MB/s | 1,414.0 MB/s | 0.79 | 0.03 |
| des-cbc | 9.8 MB/s | 19.5 MB/s | 19.6 MB/s | 0.50 | 0.50 |
| des-ede3-cbc | 3.3 MB/s | 5.2 MB/s | 6.6 MB/s | 0.63 | 0.50 |
| rc4 | 1,056.0 MB/s | 1,051.8 MB/s | 1,061.5 MB/s | 1.00 | 0.99 |
| x25519 | 11,262 op/s | 26,366 op/s | 25,444 op/s | 0.43 | 0.44 |
| ed25519-sign | 3,641 op/s | 78,189 op/s | 80,684 op/s | 0.05 | 0.05 |
| ed25519-verify | 3,707 op/s | 31,163 op/s | 32,378 op/s | 0.12 | 0.11 |
| ecdh-p224 | 3,640 op/s | 7,520 op/s | 7,527 op/s | 0.48 | 0.48 |
| ecdsa-p224-sign | 6,378 op/s | 6,611 op/s | 6,847 op/s | 0.96 | 0.93 |
| ecdsa-p224-verify | 2,975 op/s | 3,672 op/s | 3,626 op/s | 0.81 | 0.82 |
| ecdh-p256 | 2,657 op/s | 9,692 op/s | 9,681 op/s | 0.27 | 0.27 |
| ecdsa-p256-sign | 4,792 op/s | 7,923 op/s | 7,981 op/s | 0.60 | 0.60 |
| ecdsa-p256-verify | 2,197 op/s | 4,842 op/s | 4,865 op/s | 0.45 | 0.45 |
| ecdh-p384 | 820 op/s | 2,559 op/s | 2,564 op/s | 0.32 | 0.32 |
| ecdsa-p384-sign | 1,616 op/s | 2,326 op/s | 2,356 op/s | 0.69 | 0.69 |
| ecdsa-p384-verify | 699 op/s | 1,278 op/s | 1,278 op/s | 0.55 | 0.55 |
| ecdh-p521 | 406 op/s | 2,118 op/s | 2,174 op/s | 0.19 | 0.19 |
| ecdsa-p521-sign | 729 op/s | 1,552 op/s | 1,552 op/s | 0.47 | 0.47 |
| ecdsa-p521-verify | 332 op/s | 1,028 op/s | 1,028 op/s | 0.32 | 0.32 |
| rsa2048-sign | 113 op/s | 723 op/s | 722 op/s | 0.16 | 0.16 |
| rsa2048-verify | 7,503 op/s | 7,347 op/s | 7,194 op/s | 1.02 | 1.04 |
| rsa3072-sign | 39.9 op/s | 261.2 op/s | 258.5 op/s | 0.15 | 0.15 |
| rsa3072-verify | 3,142 op/s | 3,474 op/s | 3,407 op/s | 0.90 | 0.92 |
| rsa4096-sign | 16.7 op/s | 118.7 op/s | 118.7 op/s | 0.14 | 0.14 |
| rsa4096-verify | 1,755 op/s | 1,992 op/s | 1,965 op/s | 0.88 | 0.89 |
| mlkem512-keygen | 36,541 op/s | 52,852 op/s | 63,811 op/s | 0.69 | 0.57 |
| mlkem512-encaps | 33,558 op/s | 58,416 op/s | 59,304 op/s | 0.57 | 0.57 |
| mlkem512-decaps | 26,537 op/s | 45,983 op/s | 45,919 op/s | 0.58 | 0.58 |
| mlkem768-keygen | 24,473 op/s | 37,768 op/s | 37,741 op/s | 0.65 | 0.65 |
| mlkem768-encaps | 20,853 op/s | 36,094 op/s | 36,165 op/s | 0.58 | 0.58 |
| mlkem768-decaps | 16,867 op/s | 28,816 op/s | 28,845 op/s | 0.59 | 0.58 |
| mlkem1024-keygen | 15,743 op/s | 24,348 op/s | 24,378 op/s | 0.65 | 0.65 |
| mlkem1024-encaps | 13,954 op/s | 24,003 op/s | 23,789 op/s | 0.58 | 0.59 |
| mlkem1024-decaps | 11,498 op/s | 19,696 op/s | 19,666 op/s | 0.58 | 0.58 |
| pbkdf2-sha256-100k | 14.1 op/s | 26.8 op/s | 132.0 op/s | 0.53 | 0.11 |
| scrypt-n15-r8 | 17.3 op/s | 17.1 op/s | 17.4 op/s | 1.01 | 1.00 |
| argon2id-t1-64m-p4 | 33.1 op/s | 35.4 op/s | 35.5 op/s | 0.93 | 0.93 |

Without the CPU's instructions on either side, the hashes, ciphers and
ML-KEM run at 0.25 to 0.85 of Rust's speed, and RC4, scrypt and Argon2
level with it. ECDSA signing runs at 0.45 to 0.95 (P-224 is level), its
verification at 0.3 to 0.8 and ECDH at 0.2 to 0.5: the curves run
fixed-width code for each size, with complete doubling formulas, a comb
over precomputed multiples of G for keys and signatures, the comb and
sliding windows together for verification, and for P-521 a reduction
by folding at 2^521. What is left is mostly the limb width: Rust's curve
and RSA code multiplies 64-bit limbs into 128-bit products, a quarter of
the multiplications of 32-bit limbs, and Goose has no 64x64->128
multiply (a P-256 field multiplication on 64-bit limbs measured 2.9
times faster with one). dalek also signs Ed25519 from a precomputed
table of base-point multiples, where `ed25519_sign` here runs two
general scalar multiplications (one recomputes the public key). RSA
verification, with its short exponent, is level. The `rsa` crate's
private-key operation is blinded but not constant-time
(RUSTSEC-2023-0071); the one here is both.

Against Rust: BigInt. `python3 scripts/bigint_vs_rust.py [prefix]` runs
`examples/bigint_speed.goose` and `tools/rustbigbench` on the same numbers:
num-bigint 0.4.8 for the general integers, crypto-bigint 0.5.5 for the
constant-time Montgomery exponentiation (`mont-modexp`, against its
`DynResidue::pow`). A name's number is the operands' size in bits;
`divmod` divides twice that by it, and `modpow` raises a number below the
modulus to an exponent as long as it.

| Operation | Goose | Rust (num-bigint / crypto-bigint) | Goose / Rust |
|---|---:|---:|---:|
| add-256 | 29,571,042 op/s | 12,119,285 op/s | 2.44 |
| sub-256 | 31,077,336 op/s | 27,010,260 op/s | 1.15 |
| mul-256 | 7,203,596 op/s | 17,170,244 op/s | 0.42 |
| sqr-256 | 8,651,434 op/s | 17,160,164 op/s | 0.50 |
| shl-256 | 32,302,724 op/s | 14,516,297 op/s | 2.23 |
| shr-256 | 30,699,128 op/s | 17,900,610 op/s | 1.71 |
| divmod-256 | 5,052,588 op/s | 5,868,958 op/s | 0.86 |
| add-1024 | 28,156,152 op/s | 12,047,405 op/s | 2.34 |
| sub-1024 | 26,024,570 op/s | 22,320,404 op/s | 1.17 |
| mul-1024 | 766,304 op/s | 3,705,602 op/s | 0.21 |
| sqr-1024 | 1,337,920 op/s | 3,708,044 op/s | 0.36 |
| shl-1024 | 28,514,866 op/s | 14,320,645 op/s | 1.99 |
| shr-1024 | 28,268,520 op/s | 16,783,083 op/s | 1.68 |
| divmod-1024 | 620,420 op/s | 1,230,568 op/s | 0.50 |
| add-4096 | 8,527,052 op/s | 5,930,239 op/s | 1.44 |
| sub-4096 | 8,177,802 op/s | 10,932,339 op/s | 0.75 |
| mul-4096 | 84,706 op/s | 323,999 op/s | 0.26 |
| sqr-4096 | 134,386 op/s | 324,794 op/s | 0.41 |
| shl-4096 | 12,852,570 op/s | 8,429,202 op/s | 1.52 |
| shr-4096 | 10,960,422 op/s | 15,231,305 op/s | 0.72 |
| divmod-4096 | 44,536 op/s | 133,568 op/s | 0.33 |
| add-16384 | 2,094,886 op/s | 2,236,213 op/s | 0.94 |
| sub-16384 | 2,067,546 op/s | 4,290,679 op/s | 0.48 |
| mul-16384 | 8,890 op/s | 31,563 op/s | 0.28 |
| sqr-16384 | 14,055 op/s | 31,197 op/s | 0.45 |
| shl-16384 | 3,593,312 op/s | 5,385,064 op/s | 0.67 |
| shr-16384 | 3,313,558 op/s | 7,539,777 op/s | 0.44 |
| divmod-16384 | 2,886 op/s | 14,218 op/s | 0.20 |
| add-65536 | 519,238 op/s | 618,275 op/s | 0.84 |
| sub-65536 | 515,830 op/s | 1,242,723 op/s | 0.42 |
| mul-65536 | 967 op/s | 3,961 op/s | 0.24 |
| sqr-65536 | 1,525 op/s | 3,937 op/s | 0.39 |
| shl-65536 | 937,008 op/s | 1,996,277 op/s | 0.47 |
| shr-65536 | 847,836 op/s | 2,782,970 op/s | 0.30 |
| modpow-1024 | 452 op/s | 2,032 op/s | 0.22 |
| gcd-1024 | 73,537 op/s | 66,559 op/s | 1.10 |
| modinv-1024 | 21,615 op/s | 22,398 op/s | 0.97 |
| modpow-2048 | 61.1 op/s | 283 op/s | 0.22 |
| mont-modexp-2048 | 45.4 op/s | 254 op/s | 0.18 |
| modpow-4096 | 7.2 op/s | 38.2 op/s | 0.19 |
| mont-modexp-4096 | 4.5 op/s | 30.7 op/s | 0.15 |
| gcd-4096 | 2,650 op/s | 8,746 op/s | 0.30 |
| modinv-4096 | 662 op/s | 1,170 op/s | 0.57 |
| to_str-4096 | 48,179 op/s | 86,172 op/s | 0.56 |
| parse-4096 | 99,418 op/s | 349,777 op/s | 0.28 |
| to_str-65536 | 317 op/s | 1,447 op/s | 0.22 |
| parse-65536 | 792 op/s | 2,799 op/s | 0.28 |

Addition, subtraction and shifts of short numbers are ahead or even.
Multiplication is at 0.2 to 0.35 of num-bigint and squaring at 0.35 to 0.5:
num-bigint's limbs are 64 bits with 128-bit products, a quarter of the
limb multiplications, and Goose has no 64x64->128 multiply to match it.
`modpow` (about 0.2) is Montgomery with a sliding window like
num-bigint's, so what is left is mostly the limb width; `mont_modexp`
(0.15 to 0.18) is the same, constant time. Division (0.2 to 0.9) is
Algorithm D on both sides. `to_str` and `parse` of a 65536-bit number
(0.22, 0.28) split at powers of 10^9 here; before that they were
chunk-by-chunk and quadratic (0.08, 0.13).

### Caveats

- A C compiler can turn mask arithmetic back into branches, so check the
  assembly of anything that matters; `scripts/ct_timing.py` measures the
  code as built.
- The curve code is generic over the prime except for P-521's
  reduction. On the same machine OpenSSL's ECDH (specialized, with
  assembly) is 9.5 times faster on P-256 and 5.7 times on P-384.
- Compressed points are read on every curve but P-224 (P-224's
  square root would need Tonelli-Shanks). TLS 1.3 sends only uncompressed
  points; krb5's SPAKE sends compressed ones.
- Secrets are not wiped from memory.
- This code has not been audited.

## Tests

```bash
python3 scripts/run_tests.py            # every test at -O0, -O2 and --debug, plus examples/
python3 scripts/run_tests.py --native   # also built with the C compiler
python3 scripts/ct_audit.py             # BigInt only on public values (run_tests.py runs it)
python3 scripts/ct_timing.py [scale]    # timing tests of the constant-time code (about 10 s)
python3 scripts/wycheproof.py [file ...]   # Wycheproof's vectors (../wycheproof.git), about 20 minutes
python3 scripts/dudect.py [--seconds S]    # dudect's own harness on the constant-time code (x86, ../dudect.git)
python3 scripts/gen_vectors.py          # regenerate test/vectors from Python's integers
scripts/gen_rsa8192.sh                  # regenerate test/vectors/rsa8192.txt with openssl
python3 scripts/brainpool_vectors.py    # regenerate test/vectors/brainpool.txt (a venv with ecdsa and cryptography checks more)
python3 scripts/ed448_vectors.py        # regenerate test/vectors/x448.txt and ed448.txt, checked with openssl
tools/govectors.sh -check test/vectors/xcrypto.txt   # xcrypto.txt against Go's x/crypto (needs Go)
tools/govectors.sh > test/vectors/xcrypto.txt   # regenerate it
```

- `bigint_vectors`: about 7,900 differential checks against Python ints,
  covering every operation. Operands include negatives, limb-boundary values
  and sizes across the Karatsuba threshold, plus divisions built to force
  Algorithm D's correction steps.
- `bigint_api`: conversion limits, in-place forms (aliased too), parse
  errors, bytes and identities.
- `ct_ops`: the constant-time helpers against `BigInt`, `ct_mod_small`,
  `ct_div_exact` and the masked forms among them.
- `timing/ct_timing` (`scripts/ct_timing.py`, not in run_tests.py): dudect's
  method (Reparaz, Balasch and Verbauwhede, 2017). Each operation runs on
  one fixed input and on random ones, interleaved at random, and Welch's
  t-test compares their times, whole and cut at percentiles; |t| above 10
  is a leak. It covers `mont_modexp` (exponent 0 against random),
  `ct_mod_inv`, `ct_mod_small`, the RSA private operation, RSA key loading,
  X25519, ECDSA on P-256, Ed25519 signing, Camellia (one block or random
  under a key; one key or random through the key schedule) and CMAC over
  Camellia (one key or random). BigInt's `modpow` runs as a
  control and must be caught (it is, at |t| near 500; the others stay
  below 2).
- `wycheproof/wycheproof` (`scripts/wycheproof.py`, not in run_tests.py):
  Wycheproof's vectors, converted from its JSON, for every family this
  package has an API for: AES-GCM, ChaCha20- and XChaCha20-Poly1305,
  AES- and Camellia-CBC with PKCS #7, AES- and Camellia-CMAC, AES-XTS, HMAC, HKDF and PBKDF2 over SHA-1, SHA-2
  and SHA-3, ECDH and ECDSA (DER and P1363) on P-224 to P-521, secp256k1 and
  brainpoolP256r1, P384r1 and P512r1 (their ECDH public keys as
  SubjectPublicKeyInfo, parsed strictly by the script), Ed25519,
  X25519, Ed448, X448, RSA PKCS #1 v1.5 (signing, verifying, decryption), PSS and OAEP,
  DSA, ML-KEM, ML-DSA and primality. A valid test must give Wycheproof's
  output, an invalid one must be refused. What is not tried is listed with
  its reason: curves and hashes this package does not have, PSS and OAEP
  with an MGF hash other than the message's, RSA keys above 8192 bits, XTS
  ciphertext stealing, ML-DSA signing from an expanded key.
- `scripts/dudect.py` (x86 only): dudect itself (oreparaz/dudect,
  `src/dudect.h` unchanged) times `tools/dudect/targets.goose`, the
  constant-time code exported to C, in its own harness
  (`tools/dudect/harness.c`): mont_modexp, ct_mod_inv, ct_mod_small, the
  RSA private and constant-time public operations, X25519, ECDSA P-256 and
  secp256k1 and Ed25519 signing, Shamir's sharing (a split and a join in
  GF(2^8), a split in a prime field), Camellia (a block, a key schedule)
  and Camellia-CMAC; AES (a block, AES-256's key schedule), GCM's GHASH
  under a secret key, ChaCha20-Poly1305, Poly1305, HMAC-SHA-256, X25519
  with any peer's point, X448, P-256 ECDH, Ed448 signing and ML-KEM-768
  decapsulation (KyberSlash's divisions). Some targets turn the input
  into a choice between two cases, class 0 all zeros (FIXED_ZERO): the
  tag checks of AES-GCM, AES-CCM and ChaCha20-Poly1305 (a tag wrong in
  its last byte against one wrong in its first), ct_eq_bytes, ML-KEM's
  implicit rejection (a good ciphertext against a changed one), RSA PKCS
  #1 v1.5 session-key decryption (good padding against bad: Bleichenbacher,
  Marvin), RSA-OAEP's two failures (Manger), and HMAC over a CBC record
  whose length is the secret (Lucky13). Two controls must leak (an
  early-exit comparison, BigInt's modpow) and a third, constant time by
  construction, sets the machine's floor: a leak is t above 500, or above
  10 with ten times that floor's effect size. `dut_or_bytes`, the same
  loads and ORs as ct_eq_bytes without the comparison, shows what all
  zeros against random bytes does by itself: on a Xeon both show a t of
  a few hundred over 500 million measurements (an effect a hundredth of
  the noise), the control more than ct_eq_bytes, whose code clang makes
  four loads, three ORs and one compare.
- `x25519_field`: GF(2^255 − 19) arithmetic against `BigInt`, including
  non-canonical encodings.
- `x25519_rfc`: the RFC 7748 §5.2 vectors (with the 1,000-iteration chain)
  and the §6.1 key agreement.
- `x25519_vectors`: random scalars and u-coordinates against a Python
  transcription of RFC 7748.
- `x448_field`: GF(2^448 − 2^224 − 1) arithmetic against `BigInt`,
  including non-canonical encodings and limbs at the carried bound of
  either sign, where --debug's overflow checks see the largest products.
- `x448_rfc`: RFC 7748's X448 vectors (§5.2, with the 1,000-iteration
  chain) and the §6.2 key agreement. The 1,000,000-iteration chain, too
  long for the runner, gave the RFC's result in a native build (in about
  400 s).
- `x448_vectors`: random scalars (some from openssl genpkey) and
  u-coordinates, at and above p among them, from
  `scripts/ed448_vectors.py`'s transcription of RFC 7748 and remade by
  openssl; low-order points refused by `x448_shared`.
- `ed448_vectors`: all of RFC 8032's Ed448 and Ed448ph vectors (§7.4 and
  §7.5), then random seeds, messages and contexts, matching the
  transcription and openssl byte for byte. Changed messages, contexts,
  signatures and keys are rejected, as are an Ed448 signature taken as
  Ed448ph and the reverse, S ≥ L, non-canonical, off-curve and "−0" points,
  and wrong lengths.
- `mont_ops`: Montgomery multiply, exponentiation, R², reduction,
  products and `ct_mod_inv` (invertible or not) against `BigInt`.
- `sha256_vectors`: every length up to 129 bytes and longer ones, one-shot
  and in pieces, against hashlib; MGF1.
- `aes_vectors`: the S-box and its inverse on all 256 bytes, blocks at each
  key size, and CTR with counters that carry and wrap.
- `camellia_vectors` (`scripts/camellia_vectors.py`): s1 computed as
  camellia.goose computes it (A1, the AES circuit, A2, on planes) against
  RFC 3713's SBOX1 on all 256 bytes; F on random and edge inputs; RFC
  3713's Appendix A, every one-bit plaintext under the zero key (MIT's
  known-answer set, which agrees) and every one-bit key, and random blocks
  at each key size (all-zero and all-one keys among them), both ways; CBC, CFB, OFB and CTR (counters
  that wrap) through `bignum.modes`; CMAC over AES, Camellia and 3DES at
  every length around the block edges, RFC 4493's examples, and keys
  chosen so that both arms of the subkey doubling run, with altered,
  truncated, too-long and empty tags. Every vector is checked against
  openssl when made.
- `gcm_vectors`: the GCM specification's test cases 1 to 5 and random ones,
  with nonces of 12 bytes and other lengths. Every vector is also opened
  with each part tampered with in turn.
- `rsa_vectors`: PKCS #1 v1.5, PSS and OAEP under 1024-, 1025-, 1536-bit
  (e = 3) and 2048-bit keys. Outputs must match byte for byte, and changed
  inputs must be rejected. Then an 8192-bit key from openssl
  (`scripts/gen_rsa8192.sh`), the largest taken: openssl's PKCS #1 v1.5
  signature made again byte for byte, its PSS signature verified, its OAEP
  ciphertext decrypted, and changed ones refused.
- `hash_vectors`: SHA-384 and SHA-512 at lengths around the 128-byte block,
  one-shot and in pieces; HMAC with keys shorter and longer than a block;
  HKDF, including RFC 5869's first test case.
- `chacha20_vectors`: RFC 8439's AEAD example, then ChaCha20 and Poly1305
  (checked against openssl) with random keys, counters and lengths
  around the block size, and the AEAD opened with each part tampered with.
- `hash_vectors` also reads `hash2.txt`: SHA-1, SHA-224, SHA-512/t, SHA-3
  and SHAKE (read in uneven pieces) at every length around their blocks
  and rates, and HMAC with each of them.
- `mlkem_vectors`: ML-KEM-512, -768 and -1024 keys from seeds must match
  openssl byte for byte. openssl's ciphertexts must decapsulate to its
  secrets, and changed ones to its implicit rejection keys. Malformed keys
  and ciphertexts must be refused.
- `mldsa_vectors`: ML-DSA-44, -65 and -87 against openssl
  (`scripts/parity_vectors.py`): public and expanded private keys from
  seeds, deterministic signatures under empty, short and 255-byte contexts
  reproduced byte for byte (directly and through external mu), hedged
  signatures, and changed ones that must fail, malformed hint encodings
  among them. Go's crypto/mldsa agrees with every line.
- `slhdsa_vectors`: SLH-DSA, all twelve sets (`scripts/slhdsa_vectors.py`):
  openssl's keys from seeds and its deterministic signatures under empty,
  short and 255-byte contexts, with changed and wrong-length ones it
  refuses; and NIST ACVP's keys and signatures: HashSLH-DSA under each of
  the twelve pre-hashes, the internal interface, hedged signing with given
  randomness. The "f" sets are signed here three times (byte for byte),
  SHA2-128s and SHAKE-128s once, and the other "s" sets' signatures, which
  take seconds to make, are verified. Then hedged signing, a key check,
  and refusals: another context, message, pre-hash or set, a context past
  255 bytes, wrong lengths. About 15 s at -O2 and 45 s with --debug.
- `hpke_vectors`: RFC 9180's test vectors in all four modes (DHKEM over
  P-256, P-521 and X25519; HKDF-SHA256 and -SHA512; every AEAD and
  export-only) and Go's post-quantum ones (ML-KEM-512/768/1024, the three
  hybrids, the SHAKE KDFs, DHKEM P-384): derived key pairs, encapsulation,
  the key schedule, seals up to sequence number 256, and exports. Then
  fresh keys through every KEM, and refusals: tampered messages and
  encapsulated keys, wrong info or PSK, modes a KEM or KDF does not allow.
- `dsa_vectors`: DSA against openssl at (1024, 160), (2048, 224), (2048,
  256) and (3072, 256): RFC 6979 signatures over SHA-1 to SHA-512 digests
  (longer and shorter than q) reproduced byte for byte and through DER,
  openssl's random-nonce signatures, changed ones that must fail, and
  parameters generated here. Go's crypto/dsa agrees with every line.
- `xcrypto_vectors`: vectors from Go's x/crypto itself
  (`tools/govectors`, run offline against the module cache by
  `tools/govectors.sh`, whose `-check` compares instead): MD4 and
  RIPEMD-160 around the block boundaries, Salsa20, XSalsa20, HSalsa20,
  every NaCl construction (opened again, and refused when changed),
  bcrypt hashes recomputed from their salts (and, by `-check`, verified by
  Go's bcrypt), bcrypt_pbkdf (with
  OpenBSD's vectors) at lengths around its 32-byte blocks, Blowfish, CAST5, Twofish, TEA
  and XTEA blocks and CBC, and AES-XTS; RC2-CBC at 40, 64 and 128
  effective bits from openssl; RFC 2268's RC2 and RFC 2144's CAST-128
  vectors.
- `kmac_vectors`: KMAC128 and KMAC256 against NIST SP 800-185's samples
  1 to 6, and lengths the samples lack, from openssl.
- `ec_vectors`: P-256, P-384 and P-521 multiples of the generator (1, 2, n − 2,
  n − 1 and random ones), ECDH, and ECDSA matching RFC 6979 byte for byte.
  Signatures also go through DER and back. Off-curve points, bad
  encodings, out-of-range scalars, r = 0, s = n and non-minimal DER are
  all rejected.
- `ed25519_vectors`: RFC 8032's tests 1 to 3 and random ones, matching
  byte for byte. Changed messages, signatures and keys are rejected, as
  are S ≥ L and non-canonical or off-curve keys.
- `rsa_api`: generated keys, key loading checks, raw operation bounds,
  signatures and ciphertexts under the wrong key.
- `ec_vectors` also reads `ec224.txt`: P-224 the same way, with RFC 6979's
  P-224 signature.
- `brainpool_vectors`: brainpoolP256r1, P384r1 and P512r1 against
  `brainpool.txt` (`scripts/brainpool_vectors.py`): the ECDH examples of
  RFC 7027 and RFC 6932, multiples of the generator, compressed points,
  ECDH and RFC 6979 signatures, all cross-checked against openssl, the
  `ecdsa` package (signatures byte for byte) and `cryptography`, and
  signatures made by openssl and `cryptography` to verify. Bad points,
  points of P-256 and P-384, and out-of-range scalars are refused, and
  the general-a addition run on P-256 and P-384 matches theirs.
- `modes_vectors`: CBC, CFB, OFB and CTR over AES (each key size), DES and
  triple DES, at lengths around the block, each way. Also single DES and
  triple-DES blocks (with the textbook vector), MD5 and HMAC-MD5, RC4 with
  keys of 1 to 256 bytes, and PKCS #7 padding with every malformed variant
  refused. All of it is checked against openssl.
- `kdf_vectors`: BLAKE2b and BLAKE2s (keyed and not, every output length,
  in pieces) and PBKDF2 over each hash family, against hashlib; scrypt
  with RFC 7914's cases; Argon2d, Argon2i and Argon2id. The Argon2 cases
  include RFC 9106's vectors and ones from openssl with 1 to 4 lanes and
  memory past an address block.
- `extra_vectors`: XChaCha20-Poly1305 (the draft's vectors), cSHAKE (SP
  800-185's samples), Ed25519ctx and Ed25519ph (RFC 8032 §7.2 and §7.3,
  and openssl). On one 2048-bit key: OAEP over SHA-1, SHA-2 and SHA-3,
  and PKCS #1 v1.5 encryption, including openssl's own ciphertexts, with
  malformed padding refused and the session-key form left untouched.
- `blake2_vectors`: BLAKE2Xb and BLAKE2Xs, with the reference KATs at
  every length from 1 to 256 and random ones, both one-shot and read in
  uneven pieces. HMAC, HKDF and PBKDF2 over each BLAKE2 id; RSA-PSS over
  BLAKE2, and PKCS #1 v1.5 over MD5 (checked by openssl). Go's x/crypto
  and crypto/* agreed with every line when the file was made. Also
  ECDSA over BLAKE2 digests.

`scripts/crypto_vectors.py` holds the Python transcriptions behind the
AES, GCM, ChaCha20-Poly1305, RSA, EC and Ed25519 vectors (hashes, HMAC and HKDF come from
hashlib). Each transcription is first checked against its standard's
published vectors. Then, while generating, every AES, CTR, ChaCha20,
Poly1305, RSA, ECDH, ECDSA and Ed25519 vector is also checked with the `openssl` command when
it is installed. `scripts/camellia_vectors.py` (which needs openssl)
holds the Camellia and CMAC transcriptions. `scripts/extra_vectors.py`
does the same for everything
added later (with `des_ref.py`, a DES transcription). It checks cSHAKE's
transcription through openssl's KMAC, which is built on it. Its Argon2
cases and openssl's own PKCS #1 v1.5 ciphertexts come from openssl
itself, so they change when regenerated.

The compiler is found from `--goose`, then `$GOOSE`, then `goose` on PATH,
then `../goose.git/build/goose`.

## Examples

In `examples/`, run from the repository's top as `goose examples/<name>.goose`
(or from that folder).

- `pi_digits.goose`: digits of π by Machin's formula.
- `factorial.goose`: n! two ways, direct and by prime powers with
  binary splitting.
- `bigint_basics.goose`: BigInt parsing and bases, arithmetic, truncating and floor division,
  gcd, modinv and modpow, bits and bytes.
- `random_bytes.goose`: entropy's random bytes for keys and nonces, a token, a big number below a bound.
- `hashes.goose`: SHA-2, SHA-3, SHAKE and cSHAKE, BLAKE2, and the legacy hashes.
- `mac.goose`: HMAC, CMAC and Poly1305, tags checked in constant time.
- `derive_keys.goose`: HKDF, PBKDF2 and scrypt.
- `password_hash.goose`: storing and checking passwords with Argon2id and bcrypt; bcrypt_pbkdf.
- `aes_gcm_demo.goose`: sealing, opening and tamper detection, and throughput.
- `chacha20_poly1305.goose`: ChaCha20-Poly1305 records, XChaCha20-Poly1305, bare ChaCha20.
- `block_modes.goose`: CBC with padding, CTR, CFB, OFB and XTS.
- `key_wrap.goose`: AES key wrap, plain and padded, and envelope encryption.
- `legacy_ciphers.goose`: 3DES, DES, Blowfish, CAST5, Twofish, XTEA, RC2, RC4, Salsa20.
- `x25519_demo.goose`: a key exchange.
- `x448_ed448.goose`: an X448 key exchange, and Ed448 signatures with a
  context and Ed448ph, timed.
- `rsa_demo.goose`: key generation, signatures and OAEP, timed.
- `ecc_demo.goose`: ECDHE and ECDSA on P-256 and P-384, Ed25519,
  and HKDF, timed.
- `brainpool.goose`: RFC 7027's ECDH example, then ECDH, ECDSA and
  compressed points on the three Brainpool curves, timed beside P-256.
- `dsa_demo.goose`: DSA parameters, keys, random and RFC 6979 signatures.
- `ffdh_demo.goose`: finite-field Diffie-Hellman over MODP group 14, bad peer values refused.
- `mlkem_demo.goose`: ML-KEM-768 encapsulation and decapsulation.
- `mldsa_demo.goose`: ML-DSA-65 signatures, with contexts and external mu.
- `slhdsa_demo.goose`: SLH-DSA-SHAKE-128f signatures, hedged and
  deterministic, with a context and HashSLH-DSA, timed; the sizes of all
  twelve sets.
- `hpke_demo.goose`: HPKE base and auth modes, export, and X-Wing.
- `nacl_demo.goose`: NaCl secretbox, box, sealed boxes, sign and auth.
- `constant_time.goose`: the `ct` masks, select, swap and compare, Montgomery modexp and inverse.
- `speed.goose`: every primitive's throughput or rate, one line
  each; `scripts/speed_vs_openssl.py` sets it against openssl, and
  `scripts/speed_vs_rust.py` against Rust's crates (`tools/rustbench`).
- `bigint_speed.goose`: the rate of each BigInt operation by size, and of
  `mont_modexp`; `scripts/bigint_vs_rust.py` sets it against Rust's
  num-bigint and crypto-bigint (`tools/rustbigbench`).
- `bench.goose`: schoolbook vs Karatsuba by size, 10000!, 2048-bit
  modpow.
