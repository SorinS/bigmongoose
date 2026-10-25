// bigman.ct against BigInt, on random fixed-width operands and the values
// at the edges of a width (0, 1, m - 1, all ones).
import std;
import bigman from "..";
import bigman.ct;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 10 { print("FAIL ", what); } }
}

// The limbs of v at exactly n limbs.
fn limbs(v, n: i64) -> u32[>..] {
    var out: u32[>..] = [];
    for i in n { out.push(if i < v.mag.len { v.mag[i] } else { 0 }); }
    return out;
}

fn value(xs: const u32[:]) -> bigman::BigInt {
    var r = bigman::zero();
    for x in xs { r.mag.push(x); }
    bigman::mag_trim(r.mag);
    return r;
}

fn random_below(r: rng&, m, n: i64) -> u32[>..] {
    var x = bigman::zero();
    for i in n { x.mag.push(r.rand_u64() as! u32); }
    bigman::mag_trim(x.mag);
    return limbs(bigman::mod_floor(x, m), n);
}

fn main() {
    // Scalars.
    let vals: u32[6] = [0, 1, 2, 2147483648, 4294967294, 4294967295];
    for a in vals {
        check("is_zero", bigman::ct_is_zero_u32(a) == (if a == 0 { 1 } else { 0 }));
        for b in vals {
            check("eq", bigman::ct_eq_u32(a, b) == (if a == b { 1 } else { 0 }));
            check("lt", bigman::ct_lt_u32(a, b) == (if a < b { 1 } else { 0 }));
            check("select", bigman::ct_select_u32(bigman::ct_mask(1), a, b) == a);
            check("select", bigman::ct_select_u32(bigman::ct_mask(0), a, b) == b);
        }
    }
    check("eq_bytes", bigman::ct_eq_bytes("tag-123", "tag-123") == 1);
    check("eq_bytes", bigman::ct_eq_bytes("tag-123", "tag-124") == 0);

    var r = rng { 7 };
    for n in 1..9 {
        let mod_bits = n * 32 - r.rand_int(16);           // at least 16 bits, so m > 0
        var m = bigman::sub(bigman::shl(bigman::one(), mod_bits), bigman::big(r.rand_int(1000) + 1));
        let ml = limbs(m, n);
        for t in 40 {
            var a = random_below(r, m, n);
            var b = random_below(r, m, n);
            if t == 0 { a = limbs(bigman::sub(m, bigman::one()), n); b = limbs(bigman::sub(m, bigman::one()), n); }
            if t == 1 { a = limbs(bigman::zero(), n); }
            let va = value(a);
            let vb = value(b);
            var out: u32[>..] = [];
            out.resize(n, 0);
            bigman::ct_mod_add(out, a, b, ml);
            check("mod_add", bigman::eq(value(out), bigman::mod_floor(bigman::add(va, vb), m)));
            bigman::ct_mod_sub(out, a, b, ml);
            check("mod_sub", bigman::eq(value(out), bigman::mod_floor(bigman::sub(va, vb), m)));
            let c = bigman::ct_add(out, a, b);
            let sum = bigman::add(value(out), bigman::shl(bigman::big(c), 32 * n));
            check("add", bigman::eq(sum, bigman::add(va, vb)));
            check("lt", (bigman::ct_lt(a, b) == 1) == bigman::lt(va, vb));
            check("eq", (bigman::ct_eq(a, b) == 1) == bigman::eq(va, vb));
            check("eq self", bigman::ct_eq(a, a) == 1);
            check("is_zero", (bigman::ct_is_zero(a) == 1) == bigman::is_zero(va));
            var x = copy(a);
            var y = copy(b);
            bigman::ct_cswap(bigman::ct_mask(1), x, y);
            check("cswap", x == b && y == a);
            bigman::ct_cswap(bigman::ct_mask(0), x, y);
            check("cswap 0", x == b && y == a);
            bigman::ct_select(out, bigman::ct_mask(1), a, b);
            check("select", out == a);
        }
    }
    print("ct: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
