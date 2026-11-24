// bignum: arbitrary-precision signed integers.
//
// A BigInt is a sign and a magnitude of 32-bit limbs, least significant
// first, always normalized: no leading zero limbs, and zero is never
// negative. Limb products are computed in u64, so every carry is explicit.
//
// The public functions take untyped (generic) parameters, which bind a
// variable or a temporary by reference, so `add(mul(a, b), c)` copies
// nothing. Results are fresh values built in place at their destination.
// Goose rejects `x = add(x, y)` (the result would be built over its own
// input): use the in-place forms (`add_to`, `mul_to`, ...) or assign
// `copy()` of a separate result.
//
// This layer is variable-time: never use it on secret data. Its time
// follows the values (their lengths, an exponent's bits, a quotient's
// corrections), so it is for public values only. Secrets go through the
// constant-time layer:
// - `bignum.ct`: masks, selects, swaps, comparisons, fixed-width add and
//   subtract;
// - `bignum.mont`: Montgomery arithmetic, reduction, `mont_modexp`;
// - `bignum.x25519` and `bignum.x448`, and `bignum.ed25519` and
//   `bignum.ed448` signing;
// - `bignum.ec`: ECDH and ECDSA signing on the NIST curves;
// - `bignum.rsa`: key generation, key loading, the private-key operation
//   (CRT, blinded) and encryption; `bignum.dsa` signing and `bignum.ffdh`,
//   all built on `ct` and `mont`;
// - `bignum.aes`, `bignum.gcm`, `bignum.ccm`, `bignum.camellia`, `bignum.cmac`,
//   `bignum.des`, `bignum.mlkem`, `bignum.mldsa` and `bignum.slhdsa`
//   need no bignum, and are constant time themselves (SLH-DSA's secrets
//   only enter hashes; what it branches on is in the signature).
// What still uses this layer outside it works on public values only:
// RSA signature verification, DSA's domain parameters and verification,
// and the like; scripts/ct_audit.py lists each use and why.

namespace bignum;

import std;
import mont;

struct BigInt { neg: bool, mag: u32[>..] }

let BASE: u64 = 4294967296;          // 2^32
let MASK32: u64 = 4294967295;

// Below this many limbs in the shorter operand, schoolbook multiplication
// beats Karatsuba (see examples/bench.goose).
let KARATSUBA_MIN: i64 = 40;

// ---------------------------------------------------------------------------
// Magnitude kernels: little-endian limb slices, results in growable arrays.

fn mag_trim(m: u32[>..]&) {
    while m.len > 0 && m[m.len - 1] == 0 { m.pop(); }
}

fn mag_cmp(a: const u32[:], b: const u32[:]) -> i64 {
    if a.len != b.len { return if a.len < b.len { -1 } else { 1 }; }
    var i = a.len;
    while i > 0 {
        i--;
        if a[i] != b[i] { return if a[i] < b[i] { -1 } else { 1 }; }
    }
    return 0;
}

// out = a + b
fn mag_add(out: u32[>..]&, a: const u32[:], b: const u32[:]) {
    out.clear();
    let x = if a.len >= b.len { a } else { b };
    let y = if a.len >= b.len { b } else { a };
    var carry: u64 = 0;
    for i in x.len {
        let yi: u64 = if i < y.len { y[i] } else { 0 };
        let t = x[i] + yi + carry;
        out.push(t as! u32);
        carry = t >> 32;
    }
    if carry > 0 { out.push(carry as! u32); }
}

// out = a - b, for a >= b
fn mag_sub(out: u32[>..]&, a: const u32[:], b: const u32[:]) {
    out.clear();
    var borrow: u64 = 0;
    for i in a.len {
        let xi: u64 = a[i];
        let yi: u64 = if i < b.len { b[i] } else { 0 };
        let t = xi - yi - borrow;           // wraps below zero
        out.push(t as! u32);
        borrow = t >> 63;
    }
    mag_trim(out);
}

// r += a over the whole width of r (a.len <= r.len); returns the carry out.
fn add_into(r: u32[:], a: const u32[:]) -> u64 {
    var carry: u64 = 0;
    for i in r.len {
        if i >= a.len && carry == 0 { break; }
        let ai: u64 = if i < a.len { a[i] } else { 0 };
        let t = r[i] + ai + carry;
        r[i] = t as! u32;
        carry = t >> 32;
    }
    return carry;
}

// r -= a over the whole width of r (a.len <= r.len); returns the borrow out.
fn sub_into(r: u32[:], a: const u32[:]) -> u64 {
    var borrow: u64 = 0;
    for i in r.len {
        if i >= a.len && borrow == 0 { break; }
        let ri: u64 = r[i];
        let ai: u64 = if i < a.len { a[i] } else { 0 };
        let t = ri - ai - borrow;
        r[i] = t as! u32;
        borrow = t >> 63;
    }
    return borrow;
}

// r = a * b, r.len == a.len + b.len. Each row works on its own slice of r,
// so the inner loop's indices need no checks.
fn mul_school(r: u32[:], a: const u32[:], b: const u32[:]) {
    for &x in r { x = 0; }
    let n = b.len;
    for i in a.len {
        let ai: u64 = a[i];
        if ai == 0 { continue; }
        let row = r[i..i + n + 1];
        assert(row.len == n + 1);
        var carry: u64 = 0;
        for j in n {
            let t = row[j] + ai * b[j] + carry;
            row[j] = t as! u32;
            carry = t >> 32;
        }
        row[n] = carry as! u32;
    }
}

// r = a * a, r.len == 2 a.len: each cross product a[i] a[j] (i < j) once,
// the sum doubled, then the squares a[i]^2 added on the diagonal. About
// half the limb products of mul_school, which is faster below 6 limbs.
fn sqr_school(r: u32[:], a: const u32[:]) {
    if a.len < 6 { mul_school(r, a, a); return; }
    for &x in r { x = 0; }
    let n = a.len;
    for i in n {
        let ai: u64 = a[i];
        let rest = a[i + 1..];
        if ai == 0 || rest.len == 0 { continue; }
        let row = r[2 * i + 1..i + n + 1];       // r[i + j] for j > i, and the carry
        assert(row.len == rest.len + 1);
        var carry: u64 = 0;
        for k in rest.len {
            let t = row[k] + ai * rest[k] + carry;
            row[k] = t as! u32;
            carry = t >> 32;
        }
        row[rest.len] = carry as! u32;
    }
    var hi: u32 = 0;
    for &x in r {
        let v = x;
        x = (v << 1) | hi;
        hi = v >> 31;
    }
    var c: u64 = 0;
    for i in n {
        let ai: u64 = a[i];
        let sq = ai * ai;
        let d = r[2 * i..2 * i + 2];
        let lo = d[0] + (sq & MASK32) + c;
        d[0] = lo as! u32;
        let h = d[1] + (sq >> 32) + (lo >> 32);
        d[1] = h as! u32;
        c = h >> 32;
    }
}

// r = a * b, r.len == a.len + b.len, a.len >= b.len. Temporaries live on
// `scratch`, which each activation leaves as it found it.
recursive fn mul_kara(r: u32[:], a: const u32[:], b: const u32[:], scratch: u32[>..<]&) {
    if b.len < KARATSUBA_MIN { mul_school(r, a, b); return; }
    let mark = scratch.len;
    if 2 * b.len <= a.len {
        // Unbalanced: a in chunks of b's length, each product added in.
        for &x in r { x = 0; }
        for i in 2 * b.len { scratch.push(0); }
        let t = scratch[mark..];
        var off = 0;
        while off < a.len {
            let n = ::min(b.len, a.len - off);
            let tt = t[..n + b.len];
            if n >= b.len { mul_kara(tt, a[off..off + n], b, scratch); }
            else { mul_kara(tt, b, a[off..off + n], scratch); }
            add_into(r[off..], tt);
            off += n;
        }
        scratch.resize(mark);
        return;
    }
    // a = a1 * B^h + a0, b = b1 * B^h + b0, with b.len > h.
    let h = a.len / 2;
    let a0 = a[..h];
    let a1 = a[h..];
    let b0 = b[..h];
    let b1 = b[h..];
    mul_kara(r[..2 * h], a0, b0, scratch);               // z0
    mul_kara(r[2 * h..], a1, b1, scratch);               // z2
    let la = a1.len + 1;
    let lb = ::max(h, b1.len) + 1;
    for i in 2 * (la + lb) { scratch.push(0); }
    let sa = scratch[mark..mark + la];
    let sb = scratch[mark + la..mark + la + lb];
    let t = scratch[mark + la + lb..];
    copy_into(sa[..a1.len], a1);
    add_into(sa, a0);
    copy_into(sb[..b1.len], b1);
    add_into(sb, b0);
    mul_kara(t, sa, sb, scratch);                        // (a0 + a1)(b0 + b1)
    sub_into(t, r[..2 * h]);
    sub_into(t, r[2 * h..]);                             // z1, which fits r[h..]
    let room = r.len - h;
    add_into(r[h..], t[..::min(t.len, room)]);
    scratch.resize(mark);
}

// r = a * a, r.len == 2 a.len, by Karatsuba's identity for squares:
// (a1 B^h + a0)^2 = z2 B^2h + ((a0 + a1)^2 - z0 - z2) B^h + z0, with three
// half-size squarings.
recursive fn sqr_kara(r: u32[:], a: const u32[:], scratch: u32[>..<]&) {
    if a.len < KARATSUBA_MIN { sqr_school(r, a); return; }
    let mark = scratch.len;
    let h = a.len / 2;
    let a0 = a[..h];
    let a1 = a[h..];
    sqr_kara(r[..2 * h], a0, scratch);                   // z0
    sqr_kara(r[2 * h..], a1, scratch);                   // z2
    let la = a1.len + 1;
    for i in 3 * la { scratch.push(0); }
    let sa = scratch[mark..mark + la];
    let t = scratch[mark + la..];
    copy_into(sa[..a1.len], a1);
    add_into(sa, a0);
    sqr_kara(t, sa, scratch);                            // (a0 + a1)^2
    sub_into(t, r[..2 * h]);
    sub_into(t, r[2 * h..]);                             // z1, which fits r[h..]
    let room = r.len - h;
    add_into(r[h..], t[..::min(t.len, room)]);
    scratch.resize(mark);
}

// out = a * a
fn mag_sqr(out: u32[>..]&, a: const u32[:]) {
    out.clear();
    if a.len == 0 { return; }
    out.resize(2 * a.len, 0);
    if a.len < KARATSUBA_MIN {
        sqr_school(out, a);
    } else {
        var scratch: u32[>..<] = [];
        sqr_kara(out, a, scratch);
    }
    mag_trim(out);
}

// out = a * b
fn mag_mul(out: u32[>..]&, a: const u32[:], b: const u32[:]) {
    out.clear();
    if a.len == 0 || b.len == 0 { return; }
    out.resize(a.len + b.len, 0);
    let x = if a.len >= b.len { a } else { b };
    let y = if a.len >= b.len { b } else { a };
    if y.len < KARATSUBA_MIN {
        mul_school(out, x, y);
    } else {
        var scratch: u32[>..<] = [];
        mul_kara(out, x, y, scratch);
    }
    mag_trim(out);
}

// m = m * f + a, in place.
fn mag_mul_add_small(m: u32[>..]&, f: u32, a: u32) {
    var carry: u64 = a;
    for &limb in m {
        let t = limb * (f as u64) + carry;
        limb = t as! u32;
        carry = t >> 32;
    }
    if carry > 0 { m.push(carry as! u32); }
}

// q = a / d, returning a % d.
fn mag_divmod_small(q: u32[>..]&, a: const u32[:], d: u32) -> u32 {
    assert(d != 0);
    q.clear();
    q.resize(a.len, 0);
    var rem: u64 = 0;
    var i = a.len;
    while i > 0 {
        i--;
        let cur = rem << 32 | a[i];
        q[i] = (cur / d) as! u32;
        rem = cur % d;
    }
    mag_trim(q);
    return rem as! u32;
}

// m = m / d in place, returning the remainder.
fn mag_div_small_in(m: u32[>..]&, d: u32) -> u32 {
    assert(d != 0);
    var rem: u64 = 0;
    var i = m.len;
    while i > 0 {
        i--;
        let cur = rem << 32 | m[i];
        m[i] = (cur / d) as! u32;
        rem = cur % d;
    }
    mag_trim(m);
    return rem as! u32;
}

// out = a << s for 0 <= s < 32, always a.len + 1 limbs (the top may be 0).
fn shl_bits(out: u32[>..]&, a: const u32[:], s: i64) {
    out.clear();
    if s == 0 {
        for x in a { out.push(x); }
        out.push(0);
        return;
    }
    var carry: u32 = 0;
    for x in a {
        out.push(x << s | carry);
        carry = x >> (32 - s);
    }
    out.push(carry);
}

// q = a / b, r = a % b, for b != 0: Knuth's Algorithm D (TAOCP 4.3.1).
fn mag_divmod(q: u32[>..]&, r: u32[>..]&, a: const u32[:], b: const u32[:]) {
    assert(b.len > 0);
    q.clear();
    r.clear();
    if mag_cmp(a, b) < 0 {
        for x in a { r.push(x); }
        return;
    }
    if b.len == 1 {
        let rr = mag_divmod_small(q, a, b[0]);
        if rr != 0 { r.push(rr); }
        return;
    }
    let n = b.len;
    let m = a.len - n;
    // Normalize so the divisor's top limb has its high bit set.
    let s = clz(b[n - 1]) - 32;
    var vn: u32[>..] = [];
    shl_bits(vn, b, s);
    var un: u32[>..] = [];
    shl_bits(un, a, s);
    let vt: u64 = vn[n - 1];
    let vs: u64 = vn[n - 2];
    q.resize(m + 1, 0);
    var jj = m + 1;
    while jj > 0 {
        jj--;
        let j = jj;
        let num = (un[j + n] as u64) << 32 | un[j + n - 1];
        var qhat = num / vt;
        var rhat = num % vt;
        while qhat >= BASE || qhat * vs > (rhat << 32 | un[j + n - 2]) {
            qhat--;
            rhat += vt;
            if rhat >= BASE { break; }
        }
        // u -= qhat * v, over u = un[j..j + n + 1] (slices, so the inner
        // loops' indices need no checks)
        let u = un[j..j + n + 1];
        let v = vn[..n];
        assert(u.len == n + 1 && v.len == n);
        var borrow: u64 = 0;
        var carry: u64 = 0;
        for i in n {
            let p = qhat * v[i] + carry;
            carry = p >> 32;
            let ui: u64 = u[i];
            let t = ui - (p & MASK32) - borrow;
            u[i] = t as! u32;
            borrow = t >> 63;
        }
        let top: u64 = u[n];
        let t = top - carry - borrow;
        u[n] = t as! u32;
        if t >> 63 != 0 {
            // qhat was one too large: add the divisor back.
            qhat--;
            var c: u64 = 0;
            for i in n {
                let ui: u64 = u[i];
                let s2 = ui + v[i] + c;       // in u64: u32 + u32 would drop the carry
                u[i] = s2 as! u32;
                c = s2 >> 32;
            }
            u[n] = (u[n] + c) as! u32;
        }
        q[j] = qhat as! u32;
    }
    mag_trim(q);
    // The remainder is un[..n] >> s.
    for i in n {
        var x = un[i] >> s;
        if s > 0 && i + 1 < n { x = x | un[i + 1] << (32 - s); }
        r.push(x);
    }
    mag_trim(r);
}

// out = a << bits
fn mag_shl(out: u32[>..]&, a: const u32[:], bits: i64) {
    out.clear();
    if a.len == 0 { return; }
    let limbs = bits / 32;
    let s = bits % 32;
    for i in limbs { out.push(0); }
    if s == 0 {
        for x in a { out.push(x); }
    } else {
        var carry: u32 = 0;
        for x in a {
            out.push(x << s | carry);
            carry = x >> (32 - s);
        }
        if carry != 0 { out.push(carry); }
    }
}

// out = a >> bits
fn mag_shr(out: u32[>..]&, a: const u32[:], bits: i64) {
    out.clear();
    let limbs = bits / 32;
    let s = bits % 32;
    if limbs >= a.len { return; }
    for i in limbs..a.len {
        var x = a[i] >> s;
        if s > 0 && i + 1 < a.len { x = x | a[i + 1] << (32 - s); }
        out.push(x);
    }
    mag_trim(out);
}

// ---------------------------------------------------------------------------
// Construction and conversion.

fn zero() -> BigInt { BigInt { neg: false, mag: [] } }

fn one() -> BigInt { big(1) }

fn from_u64(v: u64) -> BigInt {
    var r = BigInt { neg: false, mag: [] };
    var x = v;
    while x > 0 { r.mag.push(x as! u32); x = x >> 32; }
    return r;
}

fn big(v: i64) -> BigInt {
    var r = BigInt { neg: v < 0, mag: [] };
    var x: u64 = if v < 0 { 0 - (v as! u64) } else { v as! u64 };
    while x > 0 { r.mag.push(x as! u32); x = x >> 32; }
    return r;
}

// The value of little-endian u32 limbs, as any array of them.
fn big_of(xs) -> BigInt {
    var r = zero();
    for x in xs { r.mag.push(x); }
    mag_trim(r.mag);
    return r;
}

// The value as an i64, and whether it fits.
fn to_i64(a) -> i64, bool {
    if a.mag.len > 2 { return 0, false; }
    var m: u64 = 0;
    if a.mag.len > 0 { m = a.mag[0]; }
    if a.mag.len > 1 { m = m | (a.mag[1] as u64) << 32; }
    if a.neg {
        if m > 9223372036854775808 { return 0, false; }
        return (0 - m) as! i64, true;
    }
    if m > 9223372036854775807 { return 0, false; }
    return m as! i64, true;
}

// The value as a u64, and whether it fits.
fn to_u64(a) -> u64, bool {
    if a.neg || a.mag.len > 2 { return 0, false; }
    var m: u64 = 0;
    if a.mag.len > 0 { m = a.mag[0]; }
    if a.mag.len > 1 { m = m | (a.mag[1] as u64) << 32; }
    return m, true;
}

// The nearest f64, give or take rounding in the low limbs.
fn to_f64(a) -> f64 {
    var r = 0.0;
    var i = a.mag.len;
    while i > 0 { i--; r = r * 4294967296.0 + a.mag[i]; }
    return if a.neg { -r } else { r };
}

fn is_zero(a) -> bool { a.mag.len == 0 }
fn is_neg(a) -> bool { a.neg }
fn is_odd(a) -> bool { a.mag.len > 0 && a.mag[0] & 1 != 0 }
fn is_even(a) -> bool { !is_odd(a) }

// -1, 0 or 1.
fn sign(a) -> i64 { if a.mag.len == 0 { 0 } else if a.neg { -1 } else { 1 } }

fn neg(a) -> BigInt {
    var r = copy(a);
    r.neg = !a.neg && a.mag.len > 0;
    return r;
}

fn abs(a) -> BigInt {
    var r = copy(a);
    r.neg = false;
    return r;
}

// ---------------------------------------------------------------------------
// Comparison.

fn cmp(a, b) -> i64 {
    if a.neg != b.neg { return if a.neg { -1 } else { 1 }; }
    let c = mag_cmp(a.mag, b.mag);
    return if a.neg { -c } else { c };
}

fn eq(a, b) -> bool { a.neg == b.neg && a.mag == b.mag }
fn ne(a, b) -> bool { !eq(a, b) }
fn lt(a, b) -> bool { cmp(a, b) < 0 }
fn le(a, b) -> bool { cmp(a, b) <= 0 }
fn gt(a, b) -> bool { cmp(a, b) > 0 }
fn ge(a, b) -> bool { cmp(a, b) >= 0 }

// Compares with a machine integer.
fn cmp_i64(a, v: i64) -> i64 {
    let b = big(v);
    return cmp(a, b);
}

// ---------------------------------------------------------------------------
// Arithmetic.

// r = (an ? -a : a) + (bn ? -b : b)
fn add_signed(r: BigInt&, a: const u32[:], an: bool, b: const u32[:], bn: bool) {
    if an == bn {
        mag_add(r.mag, a, b);
        r.neg = an;
    } else if mag_cmp(a, b) >= 0 {
        mag_sub(r.mag, a, b);
        r.neg = an;
    } else {
        mag_sub(r.mag, b, a);
        r.neg = bn;
    }
    if r.mag.len == 0 { r.neg = false; }
}

fn add(a, b) -> BigInt {
    var r = zero();
    add_signed(r, a.mag, a.neg, b.mag, b.neg);
    return r;
}

fn sub(a, b) -> BigInt {
    var r = zero();
    add_signed(r, a.mag, a.neg, b.mag, !b.neg);
    return r;
}

// Equal magnitudes (mul(x, x), or two equal values) take the squaring,
// found by a comparison that usually stops at the first limb.
fn mul(a, b) -> BigInt {
    var r = zero();
    if a.mag == b.mag { mag_sqr(r.mag, a.mag); } else { mag_mul(r.mag, a.mag, b.mag); }
    r.neg = r.mag.len > 0 && a.neg != b.neg;
    return r;
}

fn sqr(a) -> BigInt {
    var r = zero();
    mag_sqr(r.mag, a.mag);
    return r;
}

// Truncating division: the quotient rounds toward zero and the remainder
// has the dividend's sign, as in C. Aborts when b is zero.
fn divmod(a, b) -> BigInt, BigInt {
    assert(b.mag.len > 0);
    var q = zero();
    var r = zero();
    mag_divmod(q.mag, r.mag, a.mag, b.mag);
    q.neg = q.mag.len > 0 && a.neg != b.neg;
    r.neg = r.mag.len > 0 && a.neg;
    return q, r;
}

fn div(a, b) -> BigInt {
    assert(b.mag.len > 0);
    var q = zero();
    var r: u32[>..] = [];
    mag_divmod(q.mag, r, a.mag, b.mag);
    q.neg = q.mag.len > 0 && a.neg != b.neg;
    return q;
}

fn rem(a, b) -> BigInt {
    assert(b.mag.len > 0);
    var q: u32[>..] = [];
    var r = zero();
    mag_divmod(q, r.mag, a.mag, b.mag);
    r.neg = r.mag.len > 0 && a.neg;
    return r;
}

// Floor division: the quotient rounds down and the remainder has the
// divisor's sign, as in Python. Aborts when b is zero.
fn divmod_floor(a, b) -> BigInt, BigInt {
    var q, r = divmod(a, b);
    if r.mag.len > 0 && r.neg != b.neg {
        add_i64_to(q, -1);
        add_to(r, b);
    }
    return q, r;
}

fn div_floor(a, b) -> BigInt {
    var q, r = divmod(a, b);
    if r.mag.len > 0 && r.neg != b.neg { add_i64_to(q, -1); }
    return q;
}

// a mod b with the divisor's sign: in [0, b) for b > 0.
fn mod_floor(a, b) -> BigInt {
    var r = rem(a, b);
    if r.mag.len > 0 && r.neg != b.neg { add_to(r, b); }
    return r;
}

// ---------------------------------------------------------------------------
// In-place arithmetic: x is a variable, updated without a fresh result.

// x = x + (bn ? -b : b)
fn add_signed_to(x: BigInt&, b: const u32[:], bn: bool) {
    if x.neg == bn || x.mag.len == 0 {
        if x.mag.len == 0 { x.neg = bn; }
        while x.mag.len < b.len { x.mag.push(0); }
        let c = add_into(x.mag, b);
        if c > 0 { x.mag.push(c as! u32); }
    } else if mag_cmp(x.mag, b) >= 0 {
        sub_into(x.mag, b);
        mag_trim(x.mag);
    } else {
        // |x| < |b|: x = b - x, limb by limb in place.
        while x.mag.len < b.len { x.mag.push(0); }
        var borrow: u64 = 0;
        for i in b.len {
            let bi: u64 = b[i];
            let t = bi - x.mag[i] - borrow;
            x.mag[i] = t as! u32;
            borrow = t >> 63;
        }
        mag_trim(x.mag);
        x.neg = bn;
    }
    if x.mag.len == 0 { x.neg = false; }
}

// x += y
fn add_to(x: BigInt&, y) {
    if y.mag.len == 0 { return; }
    let t = copy(y.mag);        // y may be x itself
    add_signed_to(x, t, y.neg);
}

// x -= y
fn sub_from(x: BigInt&, y) {
    if y.mag.len == 0 { return; }
    let t = copy(y.mag);
    add_signed_to(x, t, !y.neg);
}

// x += v
fn add_i64_to(x: BigInt&, v: i64) {
    let t = big(v);
    add_signed_to(x, t.mag, t.neg);
}

// x *= y
fn mul_to(x: BigInt&, y) {
    let p = mul(x, y);
    x.mag = copy(p.mag);
    x.neg = p.neg;
}

// x = x * f + a, for x >= 0: the inner step of factorials and parsing.
fn mul_add_small_to(x: BigInt&, f: u32, a: u32) {
    assert(!x.neg);
    mag_mul_add_small(x.mag, f, a);
}

// x /= d (truncating), returning |x| % d.
fn div_small_to(x: BigInt&, d: u32) -> u32 {
    let r = mag_div_small_in(x.mag, d);
    if x.mag.len == 0 { x.neg = false; }
    return r;
}

// ---------------------------------------------------------------------------
// Bits. Shifts and the bitwise operators treat negative numbers as
// infinite two's complement, as Python does: shr rounds down and
// bit_and(-1, x) == x.

// The number of bits in |a|; 0 for zero.
fn bit_len(a) -> i64 {
    if a.mag.len == 0 { return 0; }
    return (a.mag.len - 1) * 32 + 64 - clz(a.mag[a.mag.len - 1]);
}

fn shl(a, n: i64) -> BigInt {
    assert(n >= 0);
    var r = zero();
    mag_shl(r.mag, a.mag, n);
    r.neg = a.neg && r.mag.len > 0;
    return r;
}

fn shr(a, n: i64) -> BigInt {
    assert(n >= 0);
    var r = zero();
    if !a.neg {
        mag_shr(r.mag, a.mag, n);
        return r;
    }
    // floor(-m / 2^n) == -(((m - 1) >> n) + 1)
    var m1: u32[>..] = [];
    let one_limb: u32[1] = [1];
    mag_sub(m1, a.mag, one_limb);
    mag_shr(r.mag, m1, n);
    mag_mul_add_small(r.mag, 1, 1);
    r.neg = true;
    return r;
}

// out = the n low limbs of a in two's complement.
fn to_twos(out: u32[>..]&, a: const u32[:], an: bool, n: i64) {
    out.clear();
    if !an {
        for i in n { out.push(if i < a.len { a[i] } else { 0 }); }
        return;
    }
    // -m == ~(m - 1)
    var borrow: u64 = 1;
    for i in n {
        let ai: u64 = if i < a.len { a[i] } else { 0 };
        let t = ai - borrow;
        borrow = t >> 63;
        out.push(~(t as! u32));
    }
}

// r = the value of the two's-complement limbs t.
fn from_twos(r: BigInt&, t: u32[:]) {
    r.mag.clear();
    r.neg = t.len > 0 && t[t.len - 1] >> 31 != 0;
    if r.neg {
        // m == ~t + 1
        var carry: u64 = 1;
        for x in t {
            let s = (~x) + carry;
            r.mag.push(s as! u32);
            carry = s >> 32;
        }
    } else {
        for x in t { r.mag.push(x); }
    }
    mag_trim(r.mag);
    if r.mag.len == 0 { r.neg = false; }
}

fn bit_and(a, b) -> BigInt {
    let n = ::max(a.mag.len, b.mag.len) + 1;
    var ta: u32[>..] = [];
    to_twos(ta, a.mag, a.neg, n);
    var tb: u32[>..] = [];
    to_twos(tb, b.mag, b.neg, n);
    for i in n { ta[i] = ta[i] & tb[i]; }
    var r = zero();
    from_twos(r, ta);
    return r;
}

fn bit_or(a, b) -> BigInt {
    let n = ::max(a.mag.len, b.mag.len) + 1;
    var ta: u32[>..] = [];
    to_twos(ta, a.mag, a.neg, n);
    var tb: u32[>..] = [];
    to_twos(tb, b.mag, b.neg, n);
    for i in n { ta[i] = ta[i] | tb[i]; }
    var r = zero();
    from_twos(r, ta);
    return r;
}

fn bit_xor(a, b) -> BigInt {
    let n = ::max(a.mag.len, b.mag.len) + 1;
    var ta: u32[>..] = [];
    to_twos(ta, a.mag, a.neg, n);
    var tb: u32[>..] = [];
    to_twos(tb, b.mag, b.neg, n);
    for i in n { ta[i] = ta[i] ^ tb[i]; }
    var r = zero();
    from_twos(r, ta);
    return r;
}

// ~a == -a - 1
fn bit_not(a) -> BigInt {
    var r = neg(a);
    add_i64_to(r, -1);
    return r;
}

// Bit i of a in two's complement.
fn test_bit(a, i: i64) -> bool {
    assert(i >= 0);
    let limb = i / 32;
    let n = ::max(a.mag.len, limb + 1) + 1;
    var t: u32[>..] = [];
    to_twos(t, a.mag, a.neg, n);
    return t[limb] >> (i % 32) & 1 != 0;
}

// ---------------------------------------------------------------------------
// Number theory.

// a^e
fn pow(a, e: u64) -> BigInt {
    var r = one();
    var base = copy(a);
    var k = e;
    while k > 0 {
        if k & 1 != 0 { mul_to(r, base); }
        k = k >> 1;
        if k > 0 { mul_to(base, base); }
    }
    return r;
}

// x = x mod m, in [0, m) for m > 0.
fn mod_to(x: BigInt&, m) {
    let r = mod_floor(x, m);
    x.mag = copy(r.mag);
    x.neg = r.neg;
}

// The left-to-right sliding-window schedule of e (e > 0) for windows of
// up to w bits: pairs of the squarings to do and then the odd window
// value to multiply by (0: squarings only, at the end). The first pair's
// squarings are of 1, so its value starts the result instead.
fn window_steps(steps: i64[>..]&, e: const u32[:], bits: i64, w: i64) {
    steps.clear();
    var i = bits - 1;
    var pending = 0;
    while i >= 0 {
        if (e[i / 32] >> (i % 32)) & 1 == 0 { pending++; i--; continue; }
        var j = ::max(i - w + 1, 0);
        while (e[j / 32] >> (j % 32)) & 1 == 0 { j++; }
        var v = 0;
        var k = i;
        while k >= j { v = 2 * v + ((e[k / 32] >> (k % 32)) & 1); k--; }
        steps.push(pending + i - j + 1);
        steps.push(v);
        pending = 0;
        i = j - 1;
    }
    if pending > 0 { steps.push(pending); steps.push(0); }
}

// The window width for an exponent of `bits` bits: a table of 2^(w-1) odd
// powers, against the multiplications it saves.
fn window_bits(bits: i64) -> i64 {
    if bits <= 32 { 1 } else if bits <= 256 { 4 } else if bits <= 1024 { 5 } else { 6 }
}

// r = t / R mod m for odd m and t < m R, R = 2^(32 m.len); t has 2 m.len
// limbs and is overwritten. Montgomery reduction, a row of m per limb.
fn redc(r: u32[:], t: u32[:], m: const u32[:], m0i: u32) {
    let n = m.len;
    assert(t.len == 2 * n && r.len == n);
    var extra: u64 = 0;
    for i in n {
        let row = t[i..i + n + 1];
        assert(row.len == n + 1);
        let mi: u64 = row[0] * m0i;
        var c: u64 = 0;
        for j in n {
            let s = row[j] + mi * m[j] + c;
            row[j] = s as! u32;
            c = s >> 32;
        }
        let s = row[n] + c + extra;
        row[n] = s as! u32;
        extra = s >> 32;
    }
    // t[n..] + extra R is below 2m: subtract m once if it is m or more.
    let hi = t[n..];
    var ge = extra != 0;
    if !ge {
        ge = true;
        var k = n;
        while k > 0 {
            k--;
            if hi[k] != m[k] { ge = hi[k] > m[k]; break; }
        }
    }
    if ge { sub_into(hi, m); }
    copy_into(r, hi);
}

// r = a b / R mod m (r apart from a and b), through t (2 m.len limbs).
fn mont_mul_v(r: u32[:], a: const u32[:], b: const u32[:], m: const u32[:], m0i: u32,
              t: u32[:], scratch: u32[>..<]&) {
    if m.len < KARATSUBA_MIN { mul_school(t, a, b); } else { mul_kara(t, a, b, scratch); }
    redc(r, t, m, m0i);
}

fn mont_sqr_v(r: u32[:], a: const u32[:], m: const u32[:], m0i: u32, t: u32[:], scratch: u32[>..<]&) {
    if m.len < KARATSUBA_MIN { sqr_school(t, a); } else { sqr_kara(t, a, scratch); }
    redc(r, t, m, m0i);
}

// b^e mod m for odd m > 1, 0 <= b < m and e > 0: the sliding window over
// Montgomery products, a square costing about half a product.
fn modpow_odd(b, e, m) -> BigInt {
    let n = m.mag.len;
    let m0i = mont_m0i(m.mag[0]);
    let bits = bit_len(e);
    let w = window_bits(bits);
    let odd = 1 << (w - 1);
    var steps: i64[>..] = [];
    window_steps(steps, e.mag, bits, w);
    // tab[k] = b^(2k+1) R mod m; the buffer also holds the accumulator,
    // a spare, the square of b and the double-width product.
    var buf: u32[>..] = [];
    buf.resize((odd + 5) * n, 0);
    let tab = buf[..odd * n];
    let acc = buf[odd * n..(odd + 1) * n];
    let tmp = buf[(odd + 1) * n..(odd + 2) * n];
    let b2 = buf[(odd + 2) * n..(odd + 3) * n];
    let t = buf[(odd + 3) * n..];
    var scratch: u32[>..<] = [];
    let br = mod_floor(shl(b, 32 * n), m);              // b R mod m
    copy_into(tab[..br.mag.len], br.mag);
    mont_sqr_v(b2, tab[..n], m.mag, m0i, t, scratch);
    for k in 1..odd {
        mont_mul_v(tab[k * n..(k + 1) * n], tab[(k - 1) * n..k * n], b2, m.mag, m0i, t, scratch);
    }
    let v0 = steps[1];
    copy_into(acc, tab[(v0 / 2) * n..(v0 / 2 + 1) * n]);
    var s = 2;
    while s < steps.len {
        for q in steps[s] {
            mont_sqr_v(tmp, acc, m.mag, m0i, t, scratch);
            copy_into(acc, tmp);
        }
        let v = steps[s + 1];
        if v != 0 {
            mont_mul_v(tmp, acc, tab[(v / 2) * n..(v / 2 + 1) * n], m.mag, m0i, t, scratch);
            copy_into(acc, tmp);
        }
        s += 2;
    }
    // Out of Montgomery form: acc / R.
    for &x in t { x = 0; }
    copy_into(t[..n], acc);
    var r = zero();
    r.mag.resize(n, 0);
    redc(r.mag, t, m.mag, m0i);
    mag_trim(r.mag);
    return r;
}

// b^e mod m, for e >= 0 and m > 0; in [0, m). Variable-time: an odd
// modulus takes Montgomery products with a sliding window, an even one
// the same window over products and divisions.
fn modpow(b, e, m) -> BigInt {
    assert(!e.neg && m.mag.len > 0 && !m.neg);
    if e.mag.len == 0 || (m.mag.len == 1 && m.mag[0] == 1) { return mod_floor(one(), m); }
    let base = mod_floor(b, m);
    if is_odd(m) { return modpow_odd(base, e, m); }
    let bits = bit_len(e);
    let w = window_bits(bits);
    let odd = 1 << (w - 1);
    let n = m.mag.len;
    var steps: i64[>..] = [];
    window_steps(steps, e.mag, bits, w);
    // tab[k] = b^(2k+1) mod m, each in n limbs.
    var tab: u32[>..] = [];
    tab.resize(odd * n, 0);
    copy_into(tab[..base.mag.len], base.mag);
    var b2 = mul(base, base);
    mod_to(b2, m);
    var p = copy(base);
    for k in 1..odd {
        mul_to(p, b2);
        mod_to(p, m);
        copy_into(tab[k * n..k * n + p.mag.len], p.mag);
    }
    let v0 = steps[1];
    var r = big_of(tab[(v0 / 2) * n..(v0 / 2 + 1) * n]);
    var s = 2;
    while s < steps.len {
        for q in steps[s] {
            mul_to(r, r);
            mod_to(r, m);
        }
        let v = steps[s + 1];
        if v != 0 {
            mul_to(r, big_of(tab[(v / 2) * n..(v / 2 + 1) * n]));
            mod_to(r, m);
        }
        s += 2;
    }
    return r;
}

// The bit-by-bit square-and-multiply that modpow replaced, kept as the
// reference its tests compare with.
fn modpow_simple(b, e, m) -> BigInt {
    assert(!e.neg && m.mag.len > 0 && !m.neg);
    var r = mod_floor(one(), m);
    let base = mod_floor(b, m);
    var i = bit_len(e);
    while i > 0 {
        i--;
        mul_to(r, r);
        mod_to(r, m);
        if e.mag[i / 32] >> (i % 32) & 1 != 0 {
            mul_to(r, base);
            mod_to(r, m);
        }
    }
    return r;
}

// The greatest common divisor, >= 0; gcd(0, 0) == 0.
fn gcd(a, b) -> BigInt {
    var x = abs(a);
    var y = abs(b);
    while y.mag.len > 0 {
        let r = rem(x, y);
        x = copy(y);
        y = copy(r);
    }
    return x;
}

// The least common multiple, >= 0; 0 when either is zero.
fn lcm(a, b) -> BigInt {
    if a.mag.len == 0 || b.mag.len == 0 { return zero(); }
    let g = gcd(a, b);
    var r = div(mul(a, b), g);
    r.neg = false;
    return r;
}

// g, x, y with a*x + b*y == g == gcd(a, b).
fn ext_gcd(a, b) -> BigInt, BigInt, BigInt {
    var old_r = copy(a);
    var r = copy(b);
    var old_s = one();
    var s = zero();
    var old_t = zero();
    var t = one();
    while r.mag.len > 0 {
        let q, rr = divmod_floor(old_r, r);
        old_r = copy(r);
        r = copy(rr);
        let ns = sub(old_s, mul(q, s));
        old_s = copy(s);
        s = copy(ns);
        let nt = sub(old_t, mul(q, t));
        old_t = copy(t);
        t = copy(nt);
    }
    if old_r.neg {
        old_r.neg = false;
        old_s.neg = !old_s.neg && old_s.mag.len > 0;
        old_t.neg = !old_t.neg && old_t.mag.len > 0;
    }
    return old_r, old_s, old_t;
}

// The inverse of a modulo m > 0, in [0, m), and whether it exists.
fn modinv(a, m) -> BigInt, bool {
    assert(m.mag.len > 0 && !m.neg);
    let g, x, y = ext_gcd(mod_floor(a, m), m);
    if !(g.mag.len == 1 && g.mag[0] == 1) { return zero(), false; }
    return mod_floor(x, m), true;
}

// floor(sqrt(a)), for a >= 0.
fn isqrt(a) -> BigInt {
    assert(!a.neg);
    if a.mag.len == 0 { return zero(); }
    // Newton's iteration from above: x0 = 2^ceil(bits/2) >= sqrt(a).
    var x = shl(one(), (bit_len(a) + 1) / 2);
    while true {
        var y = div(a, x);
        add_to(y, x);
        let z = shr(y, 1);
        if cmp(z, x) >= 0 { break; }
        x = copy(z);
    }
    return x;
}

// ---------------------------------------------------------------------------
// Text and bytes.

fn digit_value(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'z' { return c - 'a' + 10; }
    if c >= 'A' && c <= 'Z' { return c - 'A' + 10; }
    return 99;
}

// The largest k with base^k < 2^32, and base^k.
fn chunk_of(base: i64) -> i64, u64 {
    var k = 0;
    var p: u64 = 1;
    while p * (base as u64) < BASE { p = p * (base as u64); k++; }
    return k, p;
}

// Below these sizes text converts chunk by chunk, in quadratic time;
// above them it splits in halves at powers of base^k (k digits to a
// chunk), so the time is that of the multiplications and divisions.
let TEXT_SPLIT_LIMBS: i64 = 40;
let TEXT_SPLIT_DIGITS: i64 = 1600;

// The powers pk^(2^i) of a chunk's base, flat in buf, the i-th starting
// at at[i] and ending at at[i + 1], up to the first with more than
// `limbs` limbs.
fn chunk_powers(buf: u32[>..]&, at: i64[>..]&, pk: u64, limbs: i64) {
    buf.clear();
    at.clear();
    at.push(0);
    buf.push(pk as! u32);
    at.push(1);
    while at[at.len - 1] - at[at.len - 2] <= limbs {
        var sq: u32[>..] = [];
        mag_sqr(sq, buf[at[at.len - 2]..at[at.len - 1]]);
        buf.append(sq);
        at.push(buf.len);
    }
}

// The value of digits, chunk by chunk, and false at a digit not of base.
fn parse_small(r: u32[>..]&, digits: const u8[:], base: i64, k: i64) -> bool {
    r.clear();
    var i = 0;
    while i < digits.len {
        var chunk: u64 = 0;
        var mult: u64 = 1;
        var n = 0;
        while n < k && i < digits.len {
            let d = digit_value(digits[i]);
            if d >= base { return false; }
            chunk = chunk * (base as u64) + (d as u64);
            mult = mult * (base as u64);
            i++;
            n++;
        }
        mag_mul_add_small(r, mult as! u32, chunk as! u32);
    }
    mag_trim(r);
    return true;
}

// r = the value of digits: the high digits times pk^(2^L), plus the low
// k 2^L digits, for the largest such split. The low part waits on
// scratch while the high part is parsed. False at a digit not of base.
recursive fn parse_rec(r: u32[>..]&, digits: const u8[:], base: i64, k: i64,
                       pw: const u32[:], at: const i64[:], scratch: u32[>..<]&) -> bool {
    if digits.len < TEXT_SPLIT_DIGITS { return parse_small(r, digits, base, k); }
    var lv = 0;
    while k << (lv + 1) < digits.len { lv++; }
    let cut = digits.len - (k << lv);
    let mark = scratch.len;
    if !parse_rec(r, digits[cut..], base, k, pw, at, scratch) { return false; }
    let nlo = r.len;
    scratch.append(r);
    if !parse_rec(r, digits[..cut], base, k, pw, at, scratch) { scratch.resize(mark); return false; }
    let p = pw[at[lv]..at[lv + 1]];
    let nprod = r.len + p.len;
    for i in nprod { scratch.push(0); }
    let lo = scratch[mark..mark + nlo];
    let prod = scratch[mark + nlo..];
    if r.len >= p.len { mul_kara(prod, r, p, scratch); } else { mul_kara(prod, p, r, scratch); }
    r.clear();
    r.append(prod);
    if r.len < nlo { r.resize(nlo, 0); }
    r.push(0);
    add_into(r[..], lo);
    mag_trim(r);
    scratch.resize(mark);
    return true;
}

// Parses an optional sign and the digits of s in base 2..36 (a "0x"
// prefix is allowed in base 16), and whether s was well formed.
fn parse(s: const u8[:], base: i64 = 10) -> BigInt, bool {
    assert(base >= 2 && base <= 36);
    var r = zero();
    var i = 0;
    var negative = false;
    if i < s.len && (s[i] == '-' || s[i] == '+') { negative = s[i] == '-'; i++; }
    if base == 16 && i + 1 < s.len && s[i] == '0' && (s[i + 1] == 'x' || s[i + 1] == 'X') { i += 2; }
    if i >= s.len { return r, false; }
    let digits = s[i..];
    let k, pk = chunk_of(base);
    var ok = true;
    if digits.len < TEXT_SPLIT_DIGITS {
        ok = parse_small(r.mag, digits, base, k);
    } else {
        var pw: u32[>..] = [];
        var at: i64[>..] = [];
        chunk_powers(pw, at, pk, digits.len / k / 2 + 1);
        var scratch: u32[>..<] = [];
        ok = parse_rec(r.mag, digits, base, k, pw, at, scratch);
    }
    if !ok { return zero(), false; }
    r.neg = negative && r.mag.len > 0;
    return r, true;
}

// Appends a's digits, chunk by chunk; with width > 0, exactly width
// chunks (leading zeros), else without leading zeros (a > 0).
fn format_small(out: u8[>..]&, a: const u32[:], base: i64, k: i64, pk: u64, width: i64) {
    var work: u32[>..] = [];
    work.append(a);
    mag_trim(work);
    var chunks: u32[>..] = [];
    while work.len > 0 { chunks.push(mag_div_small_in(work, pk as! u32)); }
    while chunks.len < width { chunks.push(0); }
    var i = chunks.len;
    while i > 0 {
        i--;
        let nd = if width == 0 && i == chunks.len - 1 { 0 } else { k };
        format_uint(out, chunks[i], base, nd, '0');
    }
}

// Appends a (> 0 when width is 0), split at pk^(2^L): the quotient's
// digits, then the remainder's, padded to its 2^L chunks. With width > 0
// (a power of two), a is below pk^width and fills exactly width chunks.
// The quotient and remainder wait on scratch.
recursive fn format_rec(out: u8[>..]&, a: const u32[:], base: i64, k: i64, pk: u64, width: i64,
                        pw: const u32[:], at: const i64[:], scratch: u32[>..<]&) {
    if a.len < TEXT_SPLIT_LIMBS || width == 1 { format_small(out, a, base, k, pk, width); return; }
    var lv = 0;
    if width > 0 {
        while 2 << lv < width { lv++; }
    } else {
        while lv + 2 < at.len && 2 * (at[lv + 2] - at[lv + 1]) <= a.len + 1 { lv++; }
    }
    var top = a.len;
    while top > 0 && a[top - 1] == 0 { top--; }
    let mark = scratch.len;
    var nq = 0;
    {
        var q: u32[>..] = [];
        var r: u32[>..] = [];
        mag_divmod(q, r, a[..top], pw[at[lv]..at[lv + 1]]);
        nq = q.len;
        scratch.append(q);
        scratch.append(r);
    }
    let end = scratch.len;
    let half = 1 << lv;
    format_rec(out, scratch[mark..mark + nq], base, k, pk, if width > 0 { half } else { 0 }, pw, at, scratch);
    format_rec(out, scratch[mark + nq..end], base, k, pk, half, pw, at, scratch);
    scratch.resize(mark);
}

// Appends a in base 2..36, lowercase.
fn format_base(out: u8[>..]&, a, base: i64) {
    assert(base >= 2 && base <= 36);
    if a.mag.len == 0 { out.push('0'); return; }
    if a.neg { out.push('-'); }
    let k, pk = chunk_of(base);
    if a.mag.len < TEXT_SPLIT_LIMBS {
        format_small(out, a.mag, base, k, pk, 0);
        return;
    }
    var pw: u32[>..] = [];
    var at: i64[>..] = [];
    chunk_powers(pw, at, pk, a.mag.len / 2 + 1);
    var scratch: u32[>..<] = [];
    format_rec(out, a.mag, base, k, pk, 0, pw, at, scratch);
}

fn to_str(a, base: i64 = 10) -> u8[>..] {
    var out: u8[>..] = [];
    format_base(out, a, base);
    return out;
}

fn to_hex(a) -> u8[>..] { to_str(a, 16) }

// print(x), str(x) and format(out, x) render a BigInt in decimal.
fn format(out: u8[>..]&, v: const BigInt&) { format_base(out, v, 10); }

// The unsigned big-endian integer in bytes.
fn from_bytes_be(bytes: const u8[:]) -> BigInt {
    var r = zero();
    var i = bytes.len;
    while i > 0 {
        var limb: u32 = 0;
        var sh = 0;
        while sh < 32 && i > 0 {
            i--;
            limb = limb | (bytes[i] as u32) << sh;
            sh += 8;
        }
        r.mag.push(limb);
    }
    mag_trim(r.mag);
    return r;
}

// The unsigned little-endian integer in bytes.
fn from_bytes_le(bytes: const u8[:]) -> BigInt {
    var r = zero();
    var i = 0;
    while i < bytes.len {
        var limb: u32 = 0;
        var sh = 0;
        while sh < 32 && i < bytes.len {
            limb = limb | (bytes[i] as u32) << sh;
            sh += 8;
            i++;
        }
        r.mag.push(limb);
    }
    mag_trim(r.mag);
    return r;
}

fn byte_at(a, i: i64) -> u8 {
    let limb = i / 4;
    if limb >= a.mag.len { return 0; }
    return (a.mag[limb] >> (i % 4 * 8)) as! u8;
}

// a >= 0 as exactly `width` big-endian bytes; aborts if it does not fit.
fn to_bytes_be(a, width: i64) -> u8[>..] {
    assert(!a.neg && bit_len(a) <= 8 * width);
    var out: u8[>..] = [];
    var i = width;
    while i > 0 { i--; out.push(byte_at(a, i)); }
    return out;
}

// a >= 0 as exactly `width` little-endian bytes; aborts if it does not fit.
fn to_bytes_le(a, width: i64) -> u8[>..] {
    assert(!a.neg && bit_len(a) <= 8 * width);
    var out: u8[>..] = [];
    for i in width { out.push(byte_at(a, i)); }
    return out;
}
