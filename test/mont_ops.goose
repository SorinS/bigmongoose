// bigman.mont against BigInt: Montgomery exponentiation, R^2, reduction of
// wider numbers and exact products, for random odd moduli of 1 to 12 limbs
// and all-ones ones, with exponents of several widths, zero among them.
import std;
import bigman from "..";
import bigman.mont;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 10 { print("FAIL ", what); } }
}

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

fn random_limbs(r: rng&, n: i64) -> bigman::BigInt {
    var x = bigman::zero();
    for i in n { x.mag.push(r.rand_u64() as! u32); }
    bigman::mag_trim(x.mag);
    return x;
}

fn main() {
    check("m0i", bigman::mont_m0i(1) == 4294967295);
    for m0 in [3, 5, 65537, 4294967295] {
        let m = m0 as u32;
        check("m0i", m * bigman::mont_m0i(m) == 4294967295);   // m * (-1/m) == -1
    }
    var r = rng { 5 };
    for n in 1..13 {
        for t in 8 {
            var m = random_limbs(r, n);
            m.mag[n - 1] = m.mag[n - 1] | 1;
            m.mag[0] = m.mag[0] | 1;
            if t == 0 { m = bigman::sub(bigman::shl(bigman::one(), 32 * n), bigman::one()); }
            if t == 1 && n == 1 { m = bigman::big(3); }
            let ml = limbs(m, n);
            let m0i = bigman::mont_m0i(ml[0]);
            var r2 = limbs(bigman::zero(), n);
            bigman::mont_r2(r2, ml);
            check("r2", bigman::eq(value(r2), bigman::mod_floor(bigman::shl(bigman::one(), 64 * n), m)));

            let x = if t == 2 { bigman::sub(m, bigman::one()) } else { bigman::mod_floor(random_limbs(r, n + 1), m) };
            let e = if t == 3 { bigman::zero() } else { random_limbs(r, (t % 3) + 1) };
            var out = limbs(bigman::zero(), n);
            bigman::mont_modexp(out, limbs(x, n), limbs(e, ::max(e.mag.len, 1)), ml, m0i, r2);
            check("modexp", bigman::eq(value(out), bigman::modpow(x, e, m)));

            let y = bigman::mod_floor(random_limbs(r, n), m);
            var t1 = limbs(bigman::zero(), n);
            var t2 = limbs(bigman::zero(), n);
            var scratch = limbs(bigman::zero(), n + 2);
            bigman::mont_mul(t1, limbs(x, n), limbs(y, n), ml, m0i, scratch);
            bigman::mont_mul(t2, t1, r2, ml, m0i, scratch);
            check("mont_mul", bigman::eq(value(t2), bigman::mod_floor(bigman::mul(x, y), m)));

            let wide = random_limbs(r, 3 * n + 1);
            var red = limbs(bigman::zero(), n);
            bigman::ct_reduce(red, limbs(wide, 3 * n + 1), ml);
            check("reduce", bigman::eq(value(red), bigman::mod_floor(wide, m)));

            let a = random_limbs(r, n);
            let b = random_limbs(r, n + 2);
            var prod = limbs(bigman::zero(), 2 * n + 2);
            bigman::ct_mul(prod, limbs(a, n), limbs(b, n + 2));
            check("ct_mul", bigman::eq(value(prod), bigman::mul(a, b)));
        }
    }
    print("mont ops: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
