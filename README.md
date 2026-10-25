# bignum

Arbitrary-precision integers and constant-time arithmetic for the Goose
language, written in Goose: a foundation for cryptography.

- **`bignum`**: `BigInt`, signed integers of any size. Arithmetic,
  truncating and floor division, number theory, two's-complement bit
  operations, text in bases 2–36, and bytes. Variable-time, so never use it
  on secrets.
- **`bignum.ct`**: constant-time building blocks over fixed-width limb
  slices (masks, select, swap, compare, modular add/sub).
- **`bignum.mont`**: constant-time Montgomery arithmetic for an odd modulus
  (multiply, exponentiate, reduce).
- **`bignum.x25519`**: X25519 Diffie-Hellman (RFC 7748), constant time.
- **`bignum.ec`**: P-256, P-384 and P-521: ECDH and deterministic ECDSA
  (RFC 6979), constant time.
- **`bignum.ed25519`**: Ed25519 signatures (RFC 8032), constant-time signing.
- **`bignum.mlkem`**: ML-KEM-512/768/1024 (FIPS 203), post-quantum key
  encapsulation, constant time.
- **`bignum.rsa`**: RSA with SHA-2 (RFC 8017): key generation, PKCS #1
  v1.5 and PSS signatures, OAEP encryption; constant-time private key.
- **`bignum.aes`**: AES-128/192/256 and CTR mode, bitsliced, constant time.
- **`bignum.gcm`**: AES-GCM authenticated encryption, constant time.
- **`bignum.chacha20`**: ChaCha20, Poly1305 and ChaCha20-Poly1305 (RFC 8439).
- **`bignum.sha256`**: SHA-256, SHA-224 and MGF1.
- **`bignum.sha512`**: SHA-512, SHA-384, SHA-512/224 and SHA-512/256.
- **`bignum.sha1`**: SHA-1, for what still needs it.
- **`bignum.sha3`**: SHA3-224/256/384/512 and SHAKE128/256.
- **`bignum.hmac`**: one-shot hashing, HMAC, HKDF and MGF1 over any of them.
- **`bignum.entropy`**: random bytes from the OS (`getentropy`), for keys.

```goose
import std;
import bignum from "../bigmongoose.git";       // a path, or a git source once published

fn main() {
    let a, ok = bignum::parse("123456789012345678901234567890");
    let b = bignum::pow(bignum::big(2), 100);
    print(bignum::mul(a, b));                       // print/str/format render in decimal
    let q, r = bignum::divmod_floor(a, bignum::big(-97));
    print(q, " ", r, " ", bignum::to_hex(b));
}
```

```goose
import bignum from "../bigmongoose.git";
import bignum.x25519;

let sk, pk = bignum::x25519_keypair();
let secret, ok = bignum::x25519_shared(sk, peer_pk);   // ok is false for a low-order peer
```

```goose
import bignum from "../bigmongoose.git";
import bignum.rsa;
import bignum.gcm;

let key = bignum::rsa_generate(2048);
let pub = bignum::rsa_public(key);
let sig = bignum::rsa_sign_pss(key, msg);
let good = bignum::rsa_verify_pss(pub, msg, sig);
let ct = bignum::rsa_encrypt_oaep(pub, secret);
let pt, ok = bignum::rsa_decrypt_oaep(key, ct);

let sealed = bignum::aes_gcm_seal(key32, nonce12, aad, plaintext);   // ciphertext || tag
let opened, ok2 = bignum::aes_gcm_open(key32, nonce12, aad, sealed);  // ok2 false if tampered
```

```goose
import bignum from "../bigmongoose.git";
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
above it, with unbalanced operands split into chunks. Division is Knuth's
Algorithm D.

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
`ct_add`/`ct_sub` with carry out, `ct_cond_sub`, and `ct_mod_add`/`ct_mod_sub`,
all over `u32[:]` of a public length. `bignum.mont` builds on them:
`mont_mul` (CIOS), `mont_r2` (R² mod m by doubling, so no division by a
secret modulus), `ct_reduce` (a wide number mod m, a bit at a time), `ct_mul`,
and `mont_modexp`, which uses a 4-bit window over every bit of the
exponent's width and reads its table by scanning all 16 entries.

### RSA

| Group | Functions |
|---|---|
| Keys | `rsa_generate(bits, e = 65537)` (1024 to 4096, a multiple of 64), `rsa_key_from(n, e, d, p, q) -> key, bool`, `rsa_public_from(n, e) -> pub, bool`, `rsa_public(key)`, `rsa_bits`, `rsa_size` |
| PKCS #1 v1.5 | `rsa_sign_pkcs1(key, msg, hash = 256)`, `rsa_verify_pkcs1(pub, msg, sig, hash = 256)` |
| PSS | `rsa_sign_pss(key, msg, salt_len = -1, hash = 256)`, `rsa_sign_pss_with_salt(key, msg, salt, hash = 256)`, `rsa_verify_pss(pub, msg, sig, salt_len = -1, hash = 256)`; a salt_len of -1 means the hash's length |
| OAEP | `rsa_encrypt_oaep(pub, msg, label = "")`, `rsa_encrypt_oaep_with_seed`, `rsa_decrypt_oaep(key, ct, label = "") -> msg, bool`, `rsa_oaep_max` |
| Raw | `rsa_public_op(pub, x)`, `rsa_private_op(key, x) -> bytes, bool` |

Signatures hash with SHA-256, SHA-384 or SHA-512 (`hash` is 256, 384 or 512), with PSS's MGF1 on the same hash; OAEP uses SHA-256. A key is fixed-size limb
arrays (`u32[..128]`, so at most 4096 bits), and every function that only
needs the public half accepts a private key as well. The private operation
works by CRT. It blinds its input with r^e for a random r, and checks the
result against the public exponent before releasing it, so a fault in one
CRT half cannot leak a prime. PKCS #1 v1.5 signatures are verified by
rebuilding the encoding and comparing it whole. OAEP decryption checks
every field in constant time and reports one failure flag. PKCS #1 v1.5
*encryption* is left out on purpose (Bleichenbacher's attack).

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
lengths work too.

### ChaCha20-Poly1305

`chacha20_poly1305_seal(key, nonce, aad, pt)` / `_open` and the in-place
`_encrypt` / `_decrypt`, with the same contract as GCM: 32-byte key,
12-byte nonce, 16-byte tag, nothing released on a bad tag. The pieces are
public too: `chacha20_block`, `chacha20_xor(key, counter, nonce, data)`,
and `poly1305` one-shot or streaming. Poly1305 uses five 26-bit limbs
(after poly1305-donna-32), and its final reduction is a masked select.

### Elliptic curves

`bignum.ec` handles P-256, P-384 and P-521 with one generic
implementation. `p256()`, `p384()` and `p521()` return a `Curve` holding the field prime, the group
order, their Montgomery constants and the generator; build one and pass it
to every call. Field elements are limbs of the curve's width in Montgomery
form, multiplied by `bignum.mont`. Points are projective and added with
the complete formulas of Renes, Costello and Batina for a = −3. Those have
no exceptional cases, so doubling is just an addition and the point at
infinity needs no branch. Scalar multiplication uses 4-bit windows across
the whole scalar width and reads its table by scanning every entry.

| Group | Functions |
|---|---|
| Keys | `ec_keypair(c) -> sk, pk`, `ec_public_key(c, sk)`; private keys are `len` big-endian bytes (32 or 48), public keys the uncompressed 04 ‖ x ‖ y |
| ECDH | `ecdh_shared(c, sk, peer) -> x, bool`: false unless the peer's point is on the curve and correctly encoded |
| ECDSA | `ecdsa_sign(c, sk, msg)`, `ecdsa_verify(c, pk, msg, sig)` with SHA-256 on P-256, SHA-384 on P-384 and SHA-512 on P-521; `ecdsa_verify_digest` for any hash |
| DER | `ecdsa_sig_to_der(raw)`, `ecdsa_sig_from_der(c, der) -> raw, bool` (strict: minimal integers, no trailing bytes) |

ECDSA nonces come from RFC 6979's HMAC-DRBG, so signing needs no
randomness and the same input always gives the same signature.

`bignum.ed25519` reuses X25519's field code. It uses extended coordinates
with the RFC's complete addition, and reduces scalars mod L through
`bignum.mont`. Functions: `ed25519_keypair() -> seed, pk`,
`ed25519_public(seed)`, `ed25519_sign(seed, msg)`,
`ed25519_verify(pk, msg, sig)`. Verification uses the cofactored equation
[8]SB = [8]R + [8]kA. It rejects S ≥ L and non-canonical encodings of A
and R.

### ML-KEM

`mlkem_keygen(k)` gives a 64-byte seed (the private key, as in Go's
crypto/mlkem) and the encapsulation key; k is 2, 3 or 4 for ML-KEM-512,
-768 or -1024. `mlkem_encaps(k, ek) -> secret, ct, ok` refuses a malformed
ek (wrong length, or a coefficient of q or more). `mlkem_decaps(k, seed,
ct) -> secret, ok` and `mlkem_decaps_dk(k, dk, ct)` decapsulate, from the
seed or from the expanded key that `mlkem_keys_from_seed` gives. A
ciphertext that does not re-encrypt to itself yields the implicit
rejection key J(z ‖ c), selected with a mask. `mlkem_encaps_with` takes
the message, for tests. Every reduction mod q, including Compress's
division, is a multiply and a shift (the KyberSlash class of timing leaks
cannot occur).

### Hashes, HMAC, HKDF

Every hash comes one-shot or streaming (`*_init`, `*_update`, `*_final`):
- `sha1`;
- `sha224` and `sha256`;
- `sha384`, `sha512`, `sha512_224` and `sha512_256`;
- `sha3(bits, data)`, and `shake(bits, data, n)` with `shake_read` to
  squeeze any amount.

The generic functions name a hash by an id: 160 (SHA-1), 224, 256, 384,
512, `HASH_SHA512_224`, `HASH_SHA512_256` and `HASH_SHA3_224` through
`HASH_SHA3_512`. They include `hash_bits(id, data)`, HMAC, HKDF, MGF1, and
RSA PKCS #1 v1.5 and PSS signatures. `hmac(id, key, msg)` and the `hmac_sha256/384/512` shortcuts cover HMAC.
`hkdf_extract`, `hkdf_expand` and `hkdf` cover HKDF. TLS 1.3's HKDF-Expand-Label is a
few lines on top of `hkdf_expand` and is not included.

### Speed

Native build, Apple Silicon, clang -O2:

| Operation | Time |
|---|---|
| X25519 | 85 µs |
| Ed25519 sign / verify | 0.3 ms / 0.3 ms |
| P-256 ECDH / ECDSA sign / verify | 1.1 / 1.2 / 2.2 ms |
| P-384 ECDH / ECDSA sign / verify | 3.4 / 3.6 / 6.8 ms |
| P-521 ECDH / ECDSA sign / verify | 7.8 / 8.3 / 16 ms |
| RSA-2048 private key (sign, decrypt) | 8 ms |
| RSA-2048 public key (verify, encrypt) | 0.1 ms |
| RSA-2048 key generation | about 0.4 s on average; 30 to 870 ms over eight runs |
| ML-KEM-768 keygen / encaps / decaps | 43 / 46 / 58 µs |
| AES-256-GCM | 58 MB/s |
| ChaCha20-Poly1305 | 230 MB/s |

### Caveats

- A C compiler can turn mask arithmetic back into branches, so check the
  assembly of anything that matters.
- The P-256/P-384 code is generic over the prime. On the same machine,
  OpenSSL's ECDH (specialized, with assembly) is 27 times faster on P-256
  and 15 times faster on P-384.
- Point compression is not supported. TLS 1.3 sends only uncompressed
  points.
- Key generation and `rsa_key_from` use `BigInt` on the primes, and the
  blinding factor's inverse comes from `BigInt.modinv`, so those steps are
  not constant time. The private operation itself is.
- Secrets are not wiped from memory.
- `entropy` needs `getentropy` (macOS, Linux, BSDs), so it does not work on
  Windows.
- This code has not been audited.

## Tests

```bash
python3 scripts/run_tests.py            # every test at -O0, -O2 and --debug, plus the examples
python3 scripts/run_tests.py --native   # also built with the C compiler
python3 scripts/gen_vectors.py          # regenerate test/vectors from Python's integers
```

- `bigint_vectors`: about 7,900 differential checks against Python ints,
  covering every operation. Operands include negatives, limb-boundary values
  and sizes across the Karatsuba threshold, plus divisions built to force
  Algorithm D's correction steps.
- `bigint_api`: conversion limits, in-place forms (aliased too), parse
  errors, bytes and identities.
- `ct_ops`: the constant-time helpers against `BigInt`.
- `x25519_field`: GF(2^255 − 19) arithmetic against `BigInt`, including
  non-canonical encodings.
- `x25519_rfc`: the RFC 7748 §5.2 vectors (with the 1,000-iteration chain)
  and the §6.1 key agreement.
- `x25519_vectors`: random scalars and u-coordinates against a Python
  transcription of RFC 7748.
- `mont_ops`: Montgomery multiply, exponentiation, R², reduction and
  products against `BigInt`.
- `sha256_vectors`: every length up to 129 bytes and longer ones, one-shot
  and in pieces, against hashlib; MGF1.
- `aes_vectors`: the S-box and its inverse on all 256 bytes, blocks at each
  key size, and CTR with counters that carry and wrap.
- `gcm_vectors`: the GCM specification's test cases 1 to 5 and random ones,
  with nonces of 12 bytes and other lengths. Every vector is also opened
  with each part tampered with in turn.
- `rsa_vectors`: PKCS #1 v1.5, PSS and OAEP under 1024-, 1025-, 1536-bit
  (e = 3) and 2048-bit keys. Outputs must match byte for byte, and changed
  inputs must be rejected.
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

`scripts/crypto_vectors.py` holds the Python transcriptions behind the
AES, GCM, ChaCha20-Poly1305, RSA, EC and Ed25519 vectors (hashes, HMAC and HKDF come from
hashlib). Each transcription is first checked against its standard's
published vectors. Then, while generating, every AES, CTR, ChaCha20,
Poly1305, RSA, ECDH, ECDSA and Ed25519 vector is also checked with the `openssl` command when
it is installed.

The compiler is found from `--goose`, then `$GOOSE`, then `goose` on PATH,
then `../goose.git/build/goose`.

## Examples

- `examples/pi_digits.goose`: digits of π by Machin's formula.
- `examples/factorial.goose`: n! two ways, direct and by prime powers with
  binary splitting.
- `examples/x25519_demo.goose`: a key exchange.
- `examples/rsa_demo.goose`: key generation, signatures and OAEP, timed.
- `examples/aes_gcm_demo.goose`: sealing, opening and tamper detection, and throughput.
- `examples/ecc_demo.goose`: ECDHE and ECDSA on P-256 and P-384, Ed25519,
  and HKDF, timed.
- `examples/bench.goose`: schoolbook vs Karatsuba by size, 10000!, 2048-bit
  modpow.
