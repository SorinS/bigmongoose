// The API's edges: conversions at the limits, in-place forms (aliased
// too), bytes, parse errors, and the identities between operations.
import std;
import bigman from "..";

fn eqs(a, s: const u8[:]) -> bool { bigman::to_str(a) == s }

fn main() {
    // Conversions at the i64/u64 limits.
    let mn = bigman::big(-9223372036854775808);
    assert(eqs(mn, "-9223372036854775808"));
    let v, ok = bigman::to_i64(mn);
    assert(ok && v == -9223372036854775808);
    let below = bigman::sub(mn, bigman::one());
    let v2, ok2 = bigman::to_i64(below);
    assert(!ok2);
    let um = bigman::from_u64(18446744073709551615);
    let u, oku = bigman::to_u64(um);
    assert(oku && u == 18446744073709551615);
    let u2, oku2 = bigman::to_u64(bigman::add(um, bigman::one()));
    assert(!oku2);
    assert(bigman::to_f64(bigman::pow(bigman::big(2), 70)) == 1180591620717411303424.0);

    // Zero is never negative.
    let z = bigman::add(bigman::big(5), bigman::big(-5));
    assert(bigman::is_zero(z) && !bigman::is_neg(z) && bigman::sign(z) == 0);
    assert(!bigman::is_neg(bigman::neg(bigman::zero())));
    assert(!bigman::is_neg(bigman::mul(bigman::big(-3), bigman::zero())));
    assert(eqs(bigman::shr(bigman::big(-1), 100), "-1"));
    assert(eqs(bigman::shl(bigman::zero(), 100), "0"));

    // In-place forms, including x op= x.
    var x = bigman::big(12345);
    bigman::add_to(x, x);
    assert(eqs(x, "24690"));
    bigman::sub_from(x, x);
    assert(bigman::is_zero(x));
    x = bigman::big(-7);
    bigman::add_i64_to(x, 10);
    assert(eqs(x, "3"));
    bigman::add_i64_to(x, -10);
    assert(eqs(x, "-7"));
    bigman::mul_to(x, x);
    assert(eqs(x, "49"));
    var f = bigman::one();
    for i in 1..31 { bigman::mul_add_small_to(f, i as u32, 0); }
    assert(eqs(f, "265252859812191058636308480000000"));     // 30!
    let r = bigman::div_small_to(f, 1000000007);
    let f2 = bigman::add(bigman::mul(f, bigman::big(1000000007)), bigman::big(r));
    assert(eqs(f2, "265252859812191058636308480000000"));

    // Truncating and floor division, all sign combinations.
    for sa in 2 {
        for sb in 2 {
            let a = bigman::big(if sa == 0 { 17 } else { -17 });
            let b = bigman::big(if sb == 0 { 5 } else { -5 });
            let q, rr = bigman::divmod(a, b);
            let fq, fr = bigman::divmod_floor(a, b);
            print(a, " / ", b, ": trunc ", q, " ", rr, ", floor ", fq, " ", fr);
            assert(bigman::eq(bigman::add(bigman::mul(q, b), rr), a));
            assert(bigman::eq(bigman::add(bigman::mul(fq, b), fr), a));
        }
    }

    // Parsing.
    let p1, k1 = bigman::parse("-0x1F", 16);
    assert(k1 && eqs(p1, "-31"));
    let p2, k2 = bigman::parse("+000123");
    assert(k2 && eqs(p2, "123"));
    let p3, k3 = bigman::parse("-0");
    assert(k3 && !bigman::is_neg(p3));
    let p4, k4 = bigman::parse("12a");
    assert(!k4);
    let p5, k5 = bigman::parse("");
    assert(!k5);
    let p6, k6 = bigman::parse("-");
    assert(!k6);
    let p7, k7 = bigman::parse("zz", 36);
    assert(k7 && eqs(p7, "1295"));
    print(bigman::to_str(bigman::big(-255), 2), " ", bigman::to_str(bigman::big(1295), 36));

    // Bytes.
    let key = bigman::from_bytes_be("\x01\x02\x03\x04\x05");
    assert(bigman::to_hex(key) == "102030405");
    assert(bigman::to_bytes_be(key, 7) == "\x00\x00\x01\x02\x03\x04\x05");
    assert(bigman::to_bytes_le(key, 5) == "\x05\x04\x03\x02\x01");
    assert(bigman::eq(bigman::from_bytes_le("\x05\x04\x03\x02\x01"), key));

    // Number theory identities.
    let m = bigman::sub(bigman::pow(bigman::big(2), 127), bigman::one());   // a Mersenne prime
    let a = bigman::big(123456789);
    let inv, okinv = bigman::modinv(a, m);
    assert(okinv && eqs(bigman::mod_floor(bigman::mul(a, inv), m), "1"));
    // Fermat: a^(m-1) == 1 mod m
    assert(eqs(bigman::modpow(a, bigman::sub(m, bigman::one()), m), "1"));
    let g, gx, gy = bigman::ext_gcd(bigman::big(240), bigman::big(-46));
    print("ext_gcd(240, -46) = ", g, " ", gx, " ", gy);
    assert(bigman::eq(bigman::add(bigman::mul(bigman::big(240), gx), bigman::mul(bigman::big(-46), gy)), g));
    assert(eqs(bigman::lcm(bigman::big(-4), bigman::big(6)), "12"));
    assert(eqs(bigman::isqrt(bigman::pow(bigman::big(10), 40)), "100000000000000000000"));
    print("bit_len(2^127-1) = ", bigman::bit_len(m));
    print("ok");
}
