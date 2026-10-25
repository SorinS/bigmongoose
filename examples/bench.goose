// Timings: schoolbook against Karatsuba multiplication by operand size
// (to place KARATSUBA_MIN), and a few whole computations.
//
//   goose build examples/bench.goose && examples/bench
import std;
import os;
import bigman from "..";

fn random_limbs(r: rng&, n: i64) -> u32[>..] {
    var out: u32[>..] = [];
    for i in n { out.push((r.rand_u64() | 1) as! u32); }
    return out;
}

fn main() {
    var r = rng { 1 };
    print("limbs  schoolbook us  karatsuba us");
    let sizes: i64[10] = [16, 24, 32, 40, 48, 64, 96, 128, 256, 1024];
    for n in sizes {
        let a = random_limbs(r, n);
        let b = random_limbs(r, n);
        var out: u32[>..] = [];
        out.resize(2 * n, 0);
        var scratch: u32[>..<] = [];
        let reps = ::max(1, 2000000 / (n * n));
        var t0 = clock();
        for i in reps { bigman::mul_school(out, a, b); }
        let ts = (clock() - t0) / reps * 1000000.0;
        t0 = clock();
        for i in reps { bigman::mul_kara(out, a, b, scratch); }
        let tk = (clock() - t0) / reps * 1000000.0;
        print(n, "  ", ts, "  ", tk);
    }
    var t0 = clock();
    var f = bigman::one();
    for i in 1..10001 { bigman::mul_add_small_to(f, i as u32, 0); }
    let digits = bigman::to_str(f).len;
    print("10000! (", digits, " digits) computed and printed in ", ((clock() - t0) * 1000.0) as i64, " ms");

    t0 = clock();
    let m = bigman::sub(bigman::shl(bigman::one(), 2048), bigman::big(1557));
    let e = bigman::sub(m, bigman::big(2));
    let x = bigman::modpow(bigman::big(3), e, m);
    print("2048-bit modpow in ", ((clock() - t0) * 1000.0) as i64, " ms");

    t0 = clock();
    let big1 = bigman::pow(bigman::big(3), 200000);
    let sq = bigman::mul(big1, big1);
    print("3^200000 squared (", bigman::bit_len(sq), " bits) in ", ((clock() - t0) * 1000.0) as i64, " ms");
}
