// The GF(2^255 - 19) arithmetic of bigman.x25519 against BigInt: random
// and edge-case encodings (0, 1, p - 1, p, p + 1, 2^255 - 1, all ones),
// through each operation and through the ladder's add/sub-then-multiply.
import std;
import bigman from "..";
import bigman.x25519;

var failures = 0;
var checks = 0;

fn p25519() -> bigman::BigInt { bigman::sub(bigman::shl(bigman::one(), 255), bigman::big(19)) }

// The value an encoding stands for: the top bit dropped, reduced mod p.
fn value(b: const u8[:]) -> bigman::BigInt {
    let low = bigman::sub(bigman::shl(bigman::one(), 255), bigman::one());
    return bigman::mod_floor(bigman::bit_and(bigman::from_bytes_le(b), low), p25519());
}

fn expect(what: const u8[:], got: const u8[:], want) {
    checks++;
    let w = bigman::to_bytes_le(want, 32);
    if got != w {
        failures++;
        if failures <= 10 { print("FAIL ", what, ": got ", bigman::from_bytes_le(got), " want ", want); }
    }
}

fn encode(v) -> u8[32] {
    let b = bigman::to_bytes_le(v, 32);
    var out: u8[32] = [0; 32];
    for i in 32 { out[i] = b[i]; }
    return out;
}

fn main() {
    let p = p25519();
    var samples: u8[32][>..] = [];
    samples.push(encode(bigman::zero()));
    samples.push(encode(bigman::one()));
    samples.push(encode(bigman::sub(p, bigman::one())));
    samples.push(encode(p));
    samples.push(encode(bigman::add(p, bigman::one())));
    samples.push(encode(bigman::add(p, bigman::big(18))));                     // 2^255 - 1
    samples.push(encode(bigman::sub(bigman::shl(bigman::one(), 256), bigman::one())));   // all ones
    samples.push(encode(bigman::shl(bigman::one(), 254)));
    var r = rng { 20261025 };
    for i in 60 {
        var b: u8[32] = [0; 32];
        for j in 32 { b[j] = (r.rand_u64() & 255) as! u8; }
        samples.push(b);
    }
    let pm2 = bigman::sub(p, bigman::big(2));
    for sa in samples {
        let fa = bigman::fe_from_bytes(sa);
        let va = value(sa);
        expect("canonical", bigman::fe_to_bytes(fa), va);
        expect("sq", bigman::fe_to_bytes(bigman::fe_sq(fa)), bigman::mod_floor(bigman::mul(va, va), p));
        expect("a24", bigman::fe_to_bytes(bigman::fe_mul_a24(fa)), bigman::mod_floor(bigman::mul(va, bigman::big(121665)), p));
        expect("invert", bigman::fe_to_bytes(bigman::fe_invert(fa)), bigman::modpow(va, pm2, p));
        for sb in samples[..12] {
            let fb = bigman::fe_from_bytes(sb);
            let vb = value(sb);
            expect("mul", bigman::fe_to_bytes(bigman::fe_mul(fa, fb)), bigman::mod_floor(bigman::mul(va, vb), p));
            expect("add", bigman::fe_to_bytes(bigman::fe_add(fa, fb)), bigman::mod_floor(bigman::add(va, vb), p));
            expect("sub", bigman::fe_to_bytes(bigman::fe_sub(fa, fb)), bigman::mod_floor(bigman::sub(va, vb), p));
            // The ladder multiplies sums and differences of products.
            let s = bigman::fe_add(bigman::fe_mul(fa, fb), bigman::fe_sq(fb));
            let d = bigman::fe_sub(bigman::fe_sq(fa), bigman::fe_mul(fb, fa));
            let vs = bigman::add(bigman::mul(va, vb), bigman::mul(vb, vb));
            let vd = bigman::sub(bigman::mul(va, va), bigman::mul(vb, va));
            expect("mul(sum, diff)", bigman::fe_to_bytes(bigman::fe_mul(s, d)), bigman::mod_floor(bigman::mul(vs, vd), p));
        }
    }
    print("x25519 field: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
