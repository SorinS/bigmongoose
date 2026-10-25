// bigman.ct: constant-time building blocks over fixed-width limb slices.
//
// Nothing here branches on, or indexes by, the values it is given: only
// on lengths, which are public. A mask is 0 or 0xffffffff, and a "bit" is
// 0 or 1. Slices are little-endian u32 limbs, as in BigInt. These are the
// pieces a constant-time modular layer is built from; the C compiler can
// still undo them, so check the generated code (goose -o out.c) of
// anything that matters.

namespace bigman;

import std;

// 0 -> 0, 1 -> 0xffffffff.
fn ct_mask(bit: u32) -> u32 { 0 - (bit & 1) }

// 1 if x == 0, else 0.
fn ct_is_zero_u32(x: u32) -> u32 { ((x | (0 - x)) >> 31) ^ 1 }

// 1 if a == b, else 0.
fn ct_eq_u32(a: u32, b: u32) -> u32 { ct_is_zero_u32(a ^ b) }

// 1 if a < b, else 0.
fn ct_lt_u32(a: u32, b: u32) -> u32 { (a ^ ((a ^ b) | ((a - b) ^ b))) >> 31 }

// mask ? a : b
fn ct_select_u32(mask: u32, a: u32, b: u32) -> u32 { b ^ (mask & (a ^ b)) }

// dst = mask ? a : b, limb by limb.
fn ct_select(dst: u32[:], mask: u32, a: const u32[:], b: const u32[:]) {
    assert(dst.len == a.len && dst.len == b.len);
    for i in dst.len { dst[i] = b[i] ^ (mask & (a[i] ^ b[i])); }
}

// Swaps a and b when mask is all ones.
fn ct_cswap(mask: u32, a: u32[:], b: u32[:]) {
    assert(a.len == b.len);
    for i in a.len {
        let t = mask & (a[i] ^ b[i]);
        a[i] = a[i] ^ t;
        b[i] = b[i] ^ t;
    }
}

// 1 if every limb of a is zero, else 0.
fn ct_is_zero(a: const u32[:]) -> u32 {
    var acc: u32 = 0;
    for x in a { acc = acc | x; }
    return ct_is_zero_u32(acc);
}

// 1 if a == b, else 0; no early exit.
fn ct_eq(a: const u32[:], b: const u32[:]) -> u32 {
    assert(a.len == b.len);
    var acc: u32 = 0;
    for i in a.len { acc = acc | (a[i] ^ b[i]); }
    return ct_is_zero_u32(acc);
}

// 1 if the byte strings are equal, else 0: for comparing MACs and tags.
fn ct_eq_bytes(a: const u8[:], b: const u8[:]) -> u32 {
    assert(a.len == b.len);
    var acc: u8 = 0;
    for i in a.len { acc = acc | (a[i] ^ b[i]); }
    return ct_is_zero_u32(acc);
}

// r = a + b over the common width, returning the carry (0 or 1).
fn ct_add(r: u32[:], a: const u32[:], b: const u32[:]) -> u32 {
    assert(r.len == a.len && r.len == b.len);
    var carry: u64 = 0;
    for i in r.len {
        let ai: u64 = a[i];
        let t = ai + b[i] + carry;
        r[i] = t as! u32;
        carry = t >> 32;
    }
    return carry as! u32;
}

// r = a - b over the common width, returning the borrow (0 or 1).
fn ct_sub(r: u32[:], a: const u32[:], b: const u32[:]) -> u32 {
    assert(r.len == a.len && r.len == b.len);
    var borrow: u64 = 0;
    for i in r.len {
        let ai: u64 = a[i];
        let t = ai - b[i] - borrow;
        r[i] = t as! u32;
        borrow = t >> 63;
    }
    return borrow as! u32;
}

// 1 if a < b as numbers of the same width, else 0.
fn ct_lt(a: const u32[:], b: const u32[:]) -> u32 {
    assert(a.len == b.len);
    var borrow: u64 = 0;
    for i in a.len {
        let ai: u64 = a[i];
        let t = ai - b[i] - borrow;
        borrow = t >> 63;
    }
    return borrow as! u32;
}

// r = r - m when r >= m, else r unchanged, in the same time either way.
// `hi` is a carry limb above r (0 or 1), as an addition leaves one.
fn ct_cond_sub(r: u32[:], hi: u32, m: const u32[:]) {
    assert(r.len == m.len);
    // Subtract unconditionally, then keep the difference unless it borrowed
    // past hi.
    var borrow: u64 = 0;
    for i in r.len {
        let ri: u64 = r[i];
        let t = ri - m[i] - borrow;
        borrow = t >> 63;
    }
    let keep = ct_mask(ct_lt_u32(hi, borrow as! u32));   // hi:r < m: keep r
    borrow = 0;
    for i in r.len {
        let ri: u64 = r[i];
        let t = ri - m[i] - borrow;
        borrow = t >> 63;
        r[i] = ct_select_u32(keep, r[i], t as! u32);
    }
}

// r = (a + b) mod m, for a, b < m, all of one width.
fn ct_mod_add(r: u32[:], a: const u32[:], b: const u32[:], m: const u32[:]) {
    let c = ct_add(r, a, b);
    ct_cond_sub(r, c, m);
}

// r = (a - b) mod m, for a, b < m, all of one width.
fn ct_mod_sub(r: u32[:], a: const u32[:], b: const u32[:], m: const u32[:]) {
    let borrow = ct_sub(r, a, b);
    // Add m back when the subtraction went below zero.
    let mask = ct_mask(borrow);
    var carry: u64 = 0;
    for i in r.len {
        let ri: u64 = r[i];
        let t = ri + (m[i] & mask) + carry;
        r[i] = t as! u32;
        carry = t >> 32;
    }
}
