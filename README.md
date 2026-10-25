# bigman

Arbitrary-precision integers and constant-time arithmetic for the Goose
language, written in Goose: a foundation for cryptography.

- **`bigman`**: `BigInt`, signed integers of any size. Arithmetic,
  truncating and floor division, number theory, two's-complement bit
  operations, text in bases 2–36, and bytes. Variable-time, so never use it
  on secrets.
- **`bigman.ct`**: constant-time building blocks over fixed-width limb
  slices (masks, select, swap, compare, modular add/sub).
- **`bigman.x25519`**: X25519 Diffie-Hellman (RFC 7748), constant time.
- **`bigman.entropy`**: random bytes from the OS (`getentropy`), for keys.

```goose
import std;
import bigman from "../bigmangoose";       // a path, or a git source once published

fn main() {
    let a, ok = bigman::parse("123456789012345678901234567890");
    let b = bigman::pow(bigman::big(2), 100);
    print(bigman::mul(a, b));                       // print/str/format render in decimal
    let q, r = bigman::divmod_floor(a, bigman::big(-97));
    print(q, " ", r, " ", bigman::to_hex(b));
}
```

```goose
import bigman from "../bigmangoose";
import bigman.x25519;

let sk, pk = bigman::x25519_keypair();
let secret, ok = bigman::x25519_shared(sk, peer_pk);   // ok is false for a low-order peer
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

`bigman.x25519` keeps a field element in ten signed limbs, radix 2^25.5 as
in ref10, with unrolled multiply and square. The Montgomery ladder makes
255 fixed steps and swaps with masks. At the generated-C level, the field
ops, the ladder swap and `ct_eq_bytes` have no branches on secret data; the
only branches are on lengths and public counters. One X25519 takes about
85 µs in a native build (Apple Silicon, clang -O2).

`bigman.ct` holds masks, `ct_select`, `ct_cswap`, `ct_eq`, `ct_lt`,
`ct_add`/`ct_sub` with carry out, `ct_cond_sub`, and `ct_mod_add`/`ct_mod_sub`,
all over `u32[:]` of a public length. These are the start of a generic
constant-time modular layer (Montgomery multiplication for RSA, then P-256).

Caveats: a C compiler can turn mask arithmetic back into branches, so check
the assembly of anything that matters. Secrets are not wiped from memory.
`entropy` needs `getentropy` (macOS, Linux, BSDs), so it does not work on
Windows. This code has not been audited.

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

The compiler is found from `--goose`, then `$GOOSE`, then `goose` on PATH,
then `../goose.git/build/goose`.

## Examples

- `examples/pi_digits.goose`: digits of π by Machin's formula.
- `examples/factorial.goose`: n! two ways, direct and by prime powers with
  binary splitting.
- `examples/x25519_demo.goose`: a key exchange.
- `examples/bench.goose`: schoolbook vs Karatsuba by size, 10000!, 2048-bit
  modpow.
