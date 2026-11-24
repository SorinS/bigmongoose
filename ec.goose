// bignum.ec: the NIST curves P-224, P-256, P-384 and P-521 (y^2 = x^3 -
// 3x + b over a prime field) and the Brainpool curves brainpoolP256r1,
// P384r1 and P512r1 (y^2 = x^3 + ax + b, RFC 5639): ECDH key agreement,
// and ECDSA with SHA-224 on P-224, SHA-256 on P-256 and brainpoolP256r1,
// SHA-384 on P-384 and brainpoolP384r1 and SHA-512 on P-521 and
// brainpoolP512r1, its nonces derived deterministically (RFC 6979).
//
// One generic implementation serves all eight: field elements are
// limbs of the curve's width (7, 8, 12, 16 or 17) in Montgomery form.
// Points are projective and added and doubled by the complete formulas of
// Renes, Costello and Batina (2016: algorithms 4 and 6 for a = -3, 1 and 3
// for any a), which have no exceptional cases, so the point at infinity
// needs no branch. Scalar multiplications and inversions run in the
// fixed-width engine below (field elements u32[N], one copy of the code
// for each width), so the C compiler sees every loop's length:
// - k * p: 4-bit windows over the full scalar width, the table read by
//   scanning, so its time does not depend on the scalar or the point;
// - k * G (keys, signing): a comb with four teeth and the same scanning,
//   from precomputed 2^d G, 2^2d G and 2^3d G (scripts/ec_comb_points.py);
// - u1 G + u2 Q (verification, public scalars): the comb interleaved with
//   sliding windows, in variable time.

namespace bignum;

import std;
import bignum;
import ct;
import mont;
import hmac;
import entropy;

// The field prime p and group order n with their Montgomery constants, and
// p - 2, n - 2 for inversion by Fermat. a, b, b3 = 3b, gx and gy are in
// Montgomery form, as are the comb points cx, cy; a_is_minus3 picks the
// faster addition (public).
struct Curve {
    nl: i64, len: i64, bits: i64, hash: i64,     // limbs, bytes and bits of n, the signing hash
    p: u32[..17], p0i: u32, r2p: u32[..17], pm2: u32[..17],
    n: u32[..17], n0i: u32, r2n: u32[..17], nm2: u32[..17],
    a: u32[..17], b: u32[..17], b3: u32[..17], gx: u32[..17], gy: u32[..17],
    cx: u32[..17][3], cy: u32[..17][3],          // the comb's 2^d G, 2^2d G, 2^3d G, d = 8 nl
    a_is_minus3: bool,
}

// Projective (X : Y : Z), Montgomery form; (0 : 1 : 0) is infinity.
struct EcPoint { x: u32[..17], y: u32[..17], z: u32[..17] }

fn ec_zero(c: const Curve&) -> u32[..17] {
    var r: u32[..17] = [];
    r.resize(c.nl, 0);
    return r;
}

fn ec_limbs(c: const Curve&, v) -> u32[..17] {
    var r = ec_zero(c);
    for i in v.mag.len { r[i] = v.mag[i]; }
    return r;
}

fn ec_hex(c: const Curve&, s: const u8[:]) -> u32[..17] {
    let v, ok = parse(s, 16);
    assert(ok);
    return ec_limbs(c, v);
}

// mont_mul on fixed-size arrays, T being u32[N]: with N known to the C
// compiler the loops unroll and the sum stays in registers. The sum's two
// limbs above N are hi and top.
fn mont_mul_fixed<T>(r: T&, a: const T&, b: const T&, m: const T&, m0i: u32) {
    let n = m.len;
    var t = r;
    for &x in t { x = 0; }
    var hi: u32 = 0;
    var top: u32 = 0;
    for i in n {
        let bi: u64 = b[i];
        var c: u64 = 0;
        for j in n {
            let aj: u64 = a[j];
            let s = t[j] + aj * bi + c;
            t[j] = s as! u32;
            c = s >> 32;
        }
        let s = hi + c;
        hi = s as! u32;
        top = (s >> 32) as! u32;
        // Add mi * m, which makes the low limb zero, and shift down a limb.
        let mi: u64 = t[0] * m0i;
        let m0: u64 = m[0];
        c = (t[0] + mi * m0) >> 32;
        for j in 1..n {
            let mj: u64 = m[j];
            let s2 = t[j] + mi * mj + c;
            t[j - 1] = s2 as! u32;
            c = s2 >> 32;
        }
        let s3 = hi + c;
        t[n - 1] = s3 as! u32;
        hi = top + (s3 >> 32) as! u32;
    }
    // t < 2m: one conditional subtraction.
    fx_cond_sub(t, hi, m);
    r = t;
}

// True for P-521, whose p = 2^521 - 1 has its own multiplication (public).
fn ec_is_p521(c: const Curve&) -> bool {
    if c.nl != 17 || c.p[16] != 0x1ff { return false; }
    for i in 16 { if c.p[i] != 0xffffffff { return false; } }
    return true;
}

// The Montgomery multiplication of the fixed-width engine: mont_mul_fixed,
// or for P-521 (the only curve of 17 limbs that has mersenne set)
// p521_mont_mul, with the same result.
fn fx_mont<T>(r: T&, a: const T&, b: const T&, m: const T&, m0i: u32, mersenne: bool) {
    mont_mul_fixed(r, a, b, m, m0i);
}

fn fx_mont(r: u32[17]&, a: const u32[17]&, b: const u32[17]&, m: const u32[17]&, m0i: u32, mersenne: bool) {
    if mersenne { p521_mont_mul(r, a, b); } else { mont_mul_fixed(r, a, b, m, m0i); }
}

// a b / 2^544 mod p for p = 2^521 - 1 and a, b < p: Montgomery's product
// with R = 2^544, as mont_mul_fixed gives it, without its reduction. As
// 2^521 = 1 mod p, 2^-544 = 2^498 mod p: the product is folded at bit 521
// (t = hi 2^521 + lo = hi + lo) and the 521-bit result rotated by 498 bits.
// Shifts and additions only, in the same time for every input.
fn p521_mont_mul(r: u32[17]&, a: const u32[17]&, b: const u32[17]&) {
    // The product, a row at a time into a window w that moves down a limb
    // per row (as in mont_mul_fixed), its low limb done: t = lo + w 2^544.
    var w: u32[17] = [0; 17];
    var t: u32[34] = [0; 34];
    for i in 17 {
        let bi: u64 = b[i];
        let a0: u64 = a[0];
        let s0 = w[0] + a0 * bi;
        t[i] = s0 as! u32;
        var c: u64 = s0 >> 32;
        for j in 1..17 {
            let aj: u64 = a[j];
            let s = w[j] + aj * bi + c;
            w[j - 1] = s as! u32;
            c = s >> 32;
        }
        w[16] = c as! u32;
    }
    for i in 17 { t[17 + i] = w[i]; }
    // v = lo + hi < 2^522, hi = t >> 521 (limb i: bits 9.. of t[16 + i]).
    var v: u32[17] = [0; 17];
    var c: u64 = 0;
    for i in 17 {
        let lo: u64 = if i < 16 { t[i] } else { t[16] & 0x1ff };
        let hi: u64 = (t[16 + i] >> 9) | (t[17 + i] << 23);
        let s = lo + hi + c;
        v[i] = s as! u32;
        c = s >> 32;
    }
    // Two more folds bring v below 2^521.
    for f in 2 {
        var c2: u64 = v[16] >> 9;
        v[16] &= 0x1ff;
        for i in 17 {
            let s = v[i] + c2;
            v[i] = s as! u32;
            c2 = s >> 32;
        }
    }
    // r = v 2^498 mod p: v's low 23 bits go to the top, the rest down.
    for i in 16 { r[i] = (v[i] >> 23) | (v[i + 1] << 9); }
    r[16] = (v[0] >> 14) & 0x1ff;
    r[15] |= v[0] << 18;
    // r < 2^521, and r = p stands for 0.
    var p: u32[17] = [0xffffffff; 17];
    p[16] = 0x1ff;
    fx_cond_sub(r, 0, p);
}

// Field arithmetic mod p. The multiplication runs at the curve's width,
// a fixed size for each (the width is public).
fn fmul(c: const Curve&, a: const u32[:], b: const u32[:]) -> u32[..17] {
    var r = ec_zero(c);
    const for <N> in [7, 8, 12, 16, 17] {
        if c.nl == N {
            var x: u32[N] = [0; N];
            var y: u32[N] = [0; N];
            var m: u32[N] = [0; N];
            for i in N { x[i] = a[i]; y[i] = b[i]; m[i] = c.p[i]; }
            var z: u32[N] = [0; N];
            mont_mul_fixed(z, x, y, m, c.p0i);
            for i in N { r[i] = z[i]; }
        }
    }
    return r;
}

fn fadd(c: const Curve&, a: const u32[:], b: const u32[:]) -> u32[..17] {
    var r = ec_zero(c);
    ct_mod_add(r[..], a, b, c.p[..]);
    return r;
}

fn fsub(c: const Curve&, a: const u32[:], b: const u32[:]) -> u32[..17] {
    var r = ec_zero(c);
    ct_mod_sub(r[..], a, b, c.p[..]);
    return r;
}

fn to_mont(c: const Curve&, a: const u32[:]) -> u32[..17] { fmul(c, a, c.r2p[..]) }

fn from_mont(c: const Curve&, a: const u32[:]) -> u32[..17] {
    var one = ec_zero(c);
    one[0] = 1;
    return fmul(c, a, one[..]);
}

// 1/a mod p in normal form (0 for 0), by Fermat at the curve's width.
fn finv(c: const Curve&, a: const u32[:]) -> u32[..17] {
    return fx_inv(c, a, c.p[..], c.p0i, c.r2p[..], c.pm2[..], ec_is_p521(c));
}

// Arithmetic mod n, in normal form.
fn nmul(c: const Curve&, a: const u32[:], b: const u32[:]) -> u32[..17] {
    var r = ec_zero(c);
    var t1 = ec_zero(c);
    var t: u32[19] = [0; 19];
    mont_mul(t1[..], a, b, c.n[..], c.n0i, t[..c.nl + 2]);
    mont_mul(r[..], t1[..], c.r2n[..], c.n[..], c.n0i, t[..c.nl + 2]);
    return r;
}

fn nadd(c: const Curve&, a: const u32[:], b: const u32[:]) -> u32[..17] {
    var r = ec_zero(c);
    ct_mod_add(r[..], a, b, c.n[..]);
    return r;
}

fn ninv(c: const Curve&, a: const u32[:]) -> u32[..17] {
    return fx_inv(c, a, c.n[..], c.n0i, c.r2n[..], c.nm2[..], false);
}

// x mod n for x < 2n, as any value below p is (p < 2n on every curve here:
// n is within 2 sqrt(p) of p, the cofactor being 1).
fn nreduce(c: const Curve&, x: const u32[:]) -> u32[..17] {
    var r = ec_zero(c);
    for i in c.nl { r[i] = x[i]; }
    ct_cond_sub(r[..], 0, c.n[..]);
    return r;
}

// x -= 2, for any x >= 2 (the borrow runs through, as P-224's prime ends
// in ...0001).
fn ec_sub2(x: u32[:]) {
    var borrow: u64 = 2;
    for i in x.len {
        let t = x[i] - borrow;
        x[i] = t as! u32;
        borrow = (t >> 32) & 1;
    }
}

// A curve from its hex constants; an empty a means a = -3. comb holds the
// x and y of 2^d G, 2^2d G and 2^3d G, from scripts/ec_comb_points.py.
fn ec_curve(nl: i64, bits: i64, hash: i64, p: const u8[:], a: const u8[:], n: const u8[:],
            b: const u8[:], gx: const u8[:], gy: const u8[:], comb: const u8[:][6]) -> Curve {
    var c = Curve {
        nl: nl, len: (bits + 7) / 8, bits: bits, hash: hash,
        p: [], p0i: 0, r2p: [], pm2: [], n: [], n0i: 0, r2n: [], nm2: [],
        a: [], b: [], b3: [], gx: [], gy: [], cx: [[]; 3], cy: [[]; 3], a_is_minus3: a.len == 0,
    };
    c.p = ec_hex(c, p);
    c.n = ec_hex(c, n);
    c.p0i = mont_m0i(c.p[0]);
    c.n0i = mont_m0i(c.n[0]);
    c.r2p = ec_zero(c);
    mont_r2(c.r2p[..], c.p[..]);
    c.r2n = ec_zero(c);
    mont_r2(c.r2n[..], c.n[..]);
    c.pm2 = c.p;
    ec_sub2(c.pm2[..]);
    c.nm2 = c.n;
    ec_sub2(c.nm2[..]);
    if c.a_is_minus3 {
        var three = ec_zero(c);
        three[0] = 3;
        c.a = fsub(c, ec_zero(c)[..], to_mont(c, three[..])[..]);
    } else {
        c.a = to_mont(c, ec_hex(c, a)[..]);
    }
    c.b = to_mont(c, ec_hex(c, b)[..]);
    c.b3 = fadd(c, fadd(c, c.b[..], c.b[..])[..], c.b[..]);
    c.gx = to_mont(c, ec_hex(c, gx)[..]);
    c.gy = to_mont(c, ec_hex(c, gy)[..]);
    for i in 3 {
        c.cx[i] = to_mont(c, ec_hex(c, comb[2 * i])[..]);
        c.cy[i] = to_mont(c, ec_hex(c, comb[2 * i + 1])[..]);
    }
    return c;
}

// secp224r1 (FIPS 186-4 D.1.2.2), signing with SHA-224.
fn p224() -> Curve {
    ec_curve(7, 224, 224,
        "ffffffffffffffffffffffffffffffff000000000000000000000001",
        "",
        "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
        "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
        "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
        "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
        ["1f49bbb0f99bc52242df8d8a2a43bca7664d40ce5efd9675666ebbe9",
         "9812dd4eb8d321dc858f185310d0ece8608436e66229e0b892dc9c43",
         "0499aa8a5f8ebeefec27a4e13a0b91fb2991fab0a00641966cab26e3",
         "6916f6d4338c5b81d77aae82f70684d929610d54507510407766af5d",
         "05c73240899b4779b7619a3e7c4cc71b61d16f5c6ee28cae2df5312d",
         "72855882b08394641fab2116fd5618615165c56bda9f7f6382c73e3a"])
}

// secp256r1 (FIPS 186-4 D.1.2.3), signing with SHA-256.
fn p256() -> Curve {
    ec_curve(8, 256, 256,
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        ["0fa822bc2811aaa58492592e326e25de29493baaad651f7e90e75cb48e14db63",
         "bff44ae8f5dba80d6f4ad4bcb3df188b34b1a65050fe82f5e41124545f462ee7",
         "447d739beedb5e67fb982fd588c6766efc35ff7dc297eac357c84fc9d789bd85",
         "2d4825ab834131eee12e9d953a4aaff73d349b95a7fae5000c7e33c972e25b32",
         "a6d39677a78492762736ff8344315fc596439591a3c6b94a6cf20ffb313728be",
         "674f84749b0b881666b8babd2d27ecdf824a920c2284059bf2bab833c357f5f4"])
}

// secp384r1 (FIPS 186-4 D.1.2.4), signing with SHA-384.
fn p384() -> Curve {
    ec_curve(12, 384, 384,
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
        "",
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        ["f532389a060cbd1bd6e98b0d37ca7abc4360390918141b1a4b58808b3f8686a92c3e0c91558717db39c1b328d8ee21c9",
         "b9d2852cc3b38e696f04caa2de3a82babd22cfb2a2124163bc40ce5abe64360331ea31b1085a4e9a7a7e183923d86ecd",
         "c19e0b4c800119c440f7f9e706421279b42a31af8a3e297ddb2987894d10ddeaba065458a4f52d78a628b09aaa03bd53",
         "16f3fdbf0356b301e5a0191d1f5b77f6577a30eae3567af9c1c7cad135f6ebf2af68aa6de639d858822d0fc5e6c88c41",
         "b2d1055817cbaa12211905035f4972d7097da395a23096863d8b29dbd08848c2f33a450ad156f761e4bfc2c04905ca71",
         "354cd872c3c6cbd2237c0dba3cfd056bf82be8f52e6236c09b475d744ecf1a68e87ab07c6924666fddcebb55753ee324"])
}

// secp521r1 (FIPS 186-4 D.1.2.5), signing with SHA-512.
fn p521() -> Curve {
    ec_curve(17, 521, 512,
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "",
        "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
        "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
        "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
        "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
        ["012a0ed4082dad73df88dba377bb4188590028c343062434d0585d0f7b3a94dcfc6c4e392a4c0706c352f3f33305efc60f489e8621eb98bbdd05714c9d4d6e4a010a",
         "01fe754f22b73a1cc818c6e2c8a0949389d138c843a264de0a0675c6667b2860701a41093ffe3a0e36a71831028ec8ae469c1638c31454319374c0899758fcdadfeb",
         "006429bc4b3e190fae23ee085713e80c35ce527f7f90130f44979adc56363854b528ee67f380ce44ae8bbe3c0fc80af8d3a8acd530b6eeb9aa6c0e13c1ddcecdf0dc",
         "00f06c0d079e472ee36c319cba952363ac4357591774ff60ec49bacc18b89bee144f8d75b3f5daa4b4cc5fd3bfcf85a94659192eca92b425af8917ea6fb5dbb3838a",
         "0014509e56c3f276bf739259425f82a3c3755f337e380c33624b47f244e7da3ec391db10e381587f47a6f4383ad0048bdf6fcd94fc24ba4f85ecbca656eb512e743f",
         "01517c4c0b0a00188d5eeafd758584ade38b8e6dfa7c8647613ec842ceace628e1afa1e7e0b5ff3fffb6a36bb7bde102adb5cac386303b28185e2d65148dd94cb899"])
}

// brainpoolP256r1 (RFC 5639 §3.4), signing with SHA-256.
fn bp256() -> Curve {
    ec_curve(8, 256, 256,
        "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
        "7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
        "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
        "26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
        "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
        "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
        ["136419e3a67d29685a7673434aaa1cc83b32e8ea3b8350668855184204631f60",
         "07d0dc361277c83d3d9066c0bb112d72c6372b306ca5e1b7d70e5c8586314d01",
         "4a14c0303b856c94b44385117f87ed9d1200ca9b11006590eb6b651cf58472c9",
         "7b81e470dae2d5efe63873498b47cc5ed544a068cd732117529c5cd628f852d1",
         "635872217af20aaa27c02a8ad97c626dbdf752198773980cbeff68802cf3238c",
         "4304ea6f1a626ca6b9143f09a975138a6750f15ed5ffa7fcb9f40d86d059f9f6"])
}

// brainpoolP384r1 (RFC 5639 §3.6), signing with SHA-384.
fn bp384() -> Curve {
    ec_curve(12, 384, 384,
        "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53",
        "7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826",
        "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565",
        "04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11",
        "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e",
        "8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315",
        ["6805a4e591bc5e5d736464f23410302ecb949f8557176d8bea59b702b3968c2fe49b964240963b623eabb6097b13de62",
         "683ada314da2f247d58e253a999e3daf3dcfa9129df187b983f6b281ad438f1feb1a73ba6ee3308e74b19767a3f51e56",
         "2369dbb6397c99f18974b5688e81af98df4ddaccbb1fdc04e18a5d2d02c7f72702a353bc5345a9466bf550b04d994b04",
         "6f47b11daa3b124f93b08775925ff0a8127368f10742fa8fcd41cae93334ce6643f143e6500cb2c10ee188bb14504c85",
         "58207c45666a81e537359504199c8fb691d3a45300d2a7454f9411ba82df2bcc4f8fe27277fa6410372031b7c12fe5e5",
         "64024c6dd08b6e18ec88c58885d84dd3e2652a05dbe0778c2cc1a19feff89e71da97004db76d268ec6c911e27fbec12a"])
}

// brainpoolP512r1 (RFC 5639 §3.7), signing with SHA-512.
fn bp512() -> Curve {
    ec_curve(16, 512, 512,
        "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
        "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
        "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
        "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
        "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
        "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
        ["99b80a160886133e049b0021cd2446e988484192d78485c8bc50f8cf0c138df7319107d81f7d7a952def679aa37398dc62264dbf8e7bf823192425b7041a9902",
         "0c1352ca170be87ad8c4839810c352b116973bf46106fca30b7e6b2be4d95cbe28f1e29f557c9caab59c828a0ba1306eadcef528380e5a0a749205aa3bcb8774",
         "7b5913f766c4ed95d5262ce1b8f1b2afc056fd658f28487079a83d9b945e84601bae0f47aca3b94e97502f33730a37219d189c5408ac7da5ca448127ef66efb5",
         "3b4d8e454ffc593a3727ea1eea20b708c21fca9161306af0e46656a75fc450a8fb4edb0dbc57887724ec6f844eb496c33e9470f8da0092c9d610453cc2f45872",
         "07255cb8fb217ef74383ba6d19590b9018414a7367b30b8676d099de289796d80d921d79066727550930e38a30cb402ec62dba3f159b5d6e521ec9f72596ba28",
         "91693249bf545d573db18d862421a166abeeafd6d288df0217b1d801a1a4b506a80649d64372e6ac0147c01a39a5a40728b976e45dff80a6303785b7fec235e6"])
}

// secp256k1 (SEC 2 §2.4.1), a = 0, signing with SHA-256: Bitcoin's
// curve, which KMIP's Recommended Curve names.
fn secp256k1() -> Curve {
    ec_curve(8, 256, 256,
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        "00",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        "0000000000000000000000000000000000000000000000000000000000000007",
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        ["3322d401243c4e2582a2147c104d6ecbf774d163db0f5e5313b7e0e742d0e6bd",
         "56e70797e9664ef5bfb019bc4ddaf9b72805f63ea2873af624f3a2e96c28b2a0",
         "8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da",
         "662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82",
         "eaa649f21f51bdbae7be4ae34ce6e5217a58fdce7f47f9aa7f3b58fa2120e2b3",
         "be3279ed5bbbb03ac69a80f89879aa5a01a6b965f13f7e59d47a5305ba5ad93d"])
}

fn ec_infinity(c: const Curve&) -> EcPoint {
    var y = ec_zero(c);
    y[0] = 1;
    return EcPoint { x: ec_zero(c), y: to_mont(c, y[..]), z: ec_zero(c) };
}

fn ec_generator(c: const Curve&) -> EcPoint {
    var z = ec_zero(c);
    z[0] = 1;
    return EcPoint { x: c.gx, y: c.gy, z: to_mont(c, z[..]) };
}

// p + q by the complete formulas: algorithm 4 of Renes, Costello and Batina
// when a = -3, else their algorithm 1. The choice is the curve's, public.
fn ec_add(c: const Curve&, p: const EcPoint&, q: const EcPoint&) -> EcPoint {
    if c.a_is_minus3 { return ec_add_m3(c, p, q); }
    return ec_add_any(c, p, q);
}

// Algorithm 4 (a = -3): 12 multiplications and 2 by b.
fn ec_add_m3(c: const Curve&, p: const EcPoint&, q: const EcPoint&) -> EcPoint {
    var t0 = fmul(c, p.x[..], q.x[..]);
    var t1 = fmul(c, p.y[..], q.y[..]);
    var t2 = fmul(c, p.z[..], q.z[..]);
    var t3 = fadd(c, p.x[..], p.y[..]);
    var t4 = fadd(c, q.x[..], q.y[..]);
    t3 = fmul(c, t3[..], t4[..]);
    t4 = fadd(c, t0[..], t1[..]);
    t3 = fsub(c, t3[..], t4[..]);
    t4 = fadd(c, p.y[..], p.z[..]);
    var x3 = fadd(c, q.y[..], q.z[..]);
    t4 = fmul(c, t4[..], x3[..]);
    x3 = fadd(c, t1[..], t2[..]);
    t4 = fsub(c, t4[..], x3[..]);
    x3 = fadd(c, p.x[..], p.z[..]);
    var y3 = fadd(c, q.x[..], q.z[..]);
    x3 = fmul(c, x3[..], y3[..]);
    y3 = fadd(c, t0[..], t2[..]);
    y3 = fsub(c, x3[..], y3[..]);
    var z3 = fmul(c, c.b[..], t2[..]);
    x3 = fsub(c, y3[..], z3[..]);
    z3 = fadd(c, x3[..], x3[..]);
    x3 = fadd(c, x3[..], z3[..]);
    z3 = fsub(c, t1[..], x3[..]);
    x3 = fadd(c, t1[..], x3[..]);
    y3 = fmul(c, c.b[..], y3[..]);
    t1 = fadd(c, t2[..], t2[..]);
    t2 = fadd(c, t1[..], t2[..]);
    y3 = fsub(c, y3[..], t2[..]);
    y3 = fsub(c, y3[..], t0[..]);
    t1 = fadd(c, y3[..], y3[..]);
    y3 = fadd(c, t1[..], y3[..]);
    t1 = fadd(c, t0[..], t0[..]);
    t0 = fadd(c, t1[..], t0[..]);
    t0 = fsub(c, t0[..], t2[..]);
    t1 = fmul(c, t4[..], y3[..]);
    t2 = fmul(c, t0[..], y3[..]);
    y3 = fmul(c, x3[..], z3[..]);
    y3 = fadd(c, y3[..], t2[..]);
    x3 = fmul(c, t3[..], x3[..]);
    x3 = fsub(c, x3[..], t1[..]);
    z3 = fmul(c, t4[..], z3[..]);
    t1 = fmul(c, t3[..], t0[..]);
    z3 = fadd(c, z3[..], t1[..]);
    return EcPoint { x: x3, y: y3, z: z3 };
}

// Algorithm 1 (any a): 12 multiplications, 3 by a and 2 by b3 = 3b.
fn ec_add_any(c: const Curve&, p: const EcPoint&, q: const EcPoint&) -> EcPoint {
    var t0 = fmul(c, p.x[..], q.x[..]);
    var t1 = fmul(c, p.y[..], q.y[..]);
    var t2 = fmul(c, p.z[..], q.z[..]);
    var t3 = fadd(c, p.x[..], p.y[..]);
    var t4 = fadd(c, q.x[..], q.y[..]);
    t3 = fmul(c, t3[..], t4[..]);
    t4 = fadd(c, t0[..], t1[..]);
    t3 = fsub(c, t3[..], t4[..]);                // X1 Y2 + X2 Y1
    t4 = fadd(c, p.x[..], p.z[..]);
    var t5 = fadd(c, q.x[..], q.z[..]);
    t4 = fmul(c, t4[..], t5[..]);
    t5 = fadd(c, t0[..], t2[..]);
    t4 = fsub(c, t4[..], t5[..]);                // X1 Z2 + X2 Z1
    t5 = fadd(c, p.y[..], p.z[..]);
    var x3 = fadd(c, q.y[..], q.z[..]);
    t5 = fmul(c, t5[..], x3[..]);
    x3 = fadd(c, t1[..], t2[..]);
    t5 = fsub(c, t5[..], x3[..]);                // Y1 Z2 + Y2 Z1
    var z3 = fmul(c, c.a[..], t4[..]);
    x3 = fmul(c, c.b3[..], t2[..]);
    z3 = fadd(c, x3[..], z3[..]);
    x3 = fsub(c, t1[..], z3[..]);
    z3 = fadd(c, t1[..], z3[..]);
    var y3 = fmul(c, x3[..], z3[..]);
    t1 = fadd(c, t0[..], t0[..]);
    t1 = fadd(c, t1[..], t0[..]);
    t2 = fmul(c, c.a[..], t2[..]);
    t4 = fmul(c, c.b3[..], t4[..]);
    t1 = fadd(c, t1[..], t2[..]);
    t2 = fsub(c, t0[..], t2[..]);
    t2 = fmul(c, c.a[..], t2[..]);
    t4 = fadd(c, t4[..], t2[..]);
    t0 = fmul(c, t1[..], t4[..]);
    y3 = fadd(c, y3[..], t0[..]);
    t0 = fmul(c, t5[..], t4[..]);
    x3 = fmul(c, t3[..], x3[..]);
    x3 = fsub(c, x3[..], t0[..]);
    t0 = fmul(c, t3[..], t1[..]);
    z3 = fmul(c, t5[..], z3[..]);
    z3 = fadd(c, z3[..], t0[..]);
    return EcPoint { x: x3, y: y3, z: z3 };
}

// The fixed-width engine. Scalar multiplication and inversion run on
// field elements of type T = u32[N], N the curve's limb count, so every
// loop has a length the C compiler knows and no value goes through the
// variable-width u32[..17] of the functions above. Each entry point picks
// N with a const for over the widths of the curves here (public).
struct FCurve<T> { p: T, p0i: u32, a: T, b: T, b3: T, one: T, m3: bool, mersenne: bool }
struct FPoint<T> { x: T, y: T, z: T }

// dst = the first dst.len limbs of src.
fn fx_load<T>(dst: T&, src: const u32[:]) { for i in dst.len { dst[i] = src[i]; } }

// The curve's constants at the width of z.
fn fx_curve<T>(c: const Curve&, z: T) -> FCurve<T> {
    var k = FCurve { p: z, p0i: c.p0i, a: z, b: z, b3: z, one: z, m3: c.a_is_minus3, mersenne: ec_is_p521(c) };
    fx_load(k.p, c.p[..]);
    fx_load(k.a, c.a[..]);
    fx_load(k.b, c.b[..]);
    fx_load(k.b3, c.b3[..]);
    let inf = ec_infinity(c);              // its y is 1 in Montgomery form
    fx_load(k.one, inf.y[..]);
    return k;
}

fn fx_point<T>(p: const EcPoint&, z: T) -> FPoint<T> {
    var r = FPoint { x: z, y: z, z: z };
    fx_load(r.x, p.x[..]);
    fx_load(r.y, p.y[..]);
    fx_load(r.z, p.z[..]);
    return r;
}

fn fx_store<T>(c: const Curve&, p: const FPoint<T>&) -> EcPoint {
    var r = ec_infinity(c);
    for i in p.x.len {
        r.x[i] = p.x[i];
        r.y[i] = p.y[i];
        r.z[i] = p.z[i];
    }
    return r;
}

// r = r - m when hi:r >= m, else r unchanged, in the same time either way.
fn fx_cond_sub<T>(r: T&, hi: u32, m: const T&) {
    var d = r;
    var borrow: u64 = 0;
    for i in r.len {
        let ri: u64 = r[i];
        let t = ri - m[i] - borrow;
        d[i] = t as! u32;
        borrow = t >> 63;
    }
    let keep = ct_mask(ct_lt_u32(hi, borrow as! u32));   // hi:r < m: keep r
    for i in r.len { r[i] = ct_select_u32(keep, r[i], d[i]); }
}

fn fxm<T>(k: const FCurve<T>&, a: const T&, b: const T&) -> T {
    var r = a;
    fx_mont(r, a, b, k.p, k.p0i, k.mersenne);
    return r;
}

fn fxa<T>(k: const FCurve<T>&, a: const T&, b: const T&) -> T {
    var r = a;
    var c: u64 = 0;
    for i in r.len {
        let ai: u64 = a[i];
        let s = ai + b[i] + c;
        r[i] = s as! u32;
        c = s >> 32;
    }
    fx_cond_sub(r, c as! u32, k.p);
    return r;
}

fn fxs<T>(k: const FCurve<T>&, a: const T&, b: const T&) -> T {
    var r = a;
    var borrow: u64 = 0;
    for i in r.len {
        let ai: u64 = a[i];
        let t = ai - b[i] - borrow;
        r[i] = t as! u32;
        borrow = t >> 63;
    }
    // Add p back when the subtraction went below zero.
    let mask = ct_mask(borrow as! u32);
    var c: u64 = 0;
    for i in r.len {
        let ri: u64 = r[i];
        let t = ri + (k.p[i] & mask) + c;
        r[i] = t as! u32;
        c = t >> 32;
    }
    return r;
}

// p + q and 2p by the complete formulas of Renes, Costello and Batina:
// algorithms 4 and 6 when a = -3, else 1 and 3 (12 multiplications for an
// addition, 8 and 3 squarings for a doubling). None has an exceptional
// case, so infinity and p = q need no branch.
fn fx_add<T>(k: const FCurve<T>&, p: const FPoint<T>&, q: const FPoint<T>&) -> FPoint<T> {
    if k.m3 { return fx_add_m3(k, p, q); }
    return fx_add_any(k, p, q);
}

fn fx_dbl<T>(k: const FCurve<T>&, p: const FPoint<T>&) -> FPoint<T> {
    if k.m3 { return fx_dbl_m3(k, p); }
    return fx_dbl_any(k, p);
}

fn fx_add_m3<T>(k: const FCurve<T>&, p: const FPoint<T>&, q: const FPoint<T>&) -> FPoint<T> {
    var t0 = fxm(k, p.x, q.x);
    var t1 = fxm(k, p.y, q.y);
    var t2 = fxm(k, p.z, q.z);
    var t3 = fxa(k, p.x, p.y);
    var t4 = fxa(k, q.x, q.y);
    t3 = fxm(k, t3, t4);
    t4 = fxa(k, t0, t1);
    t3 = fxs(k, t3, t4);
    t4 = fxa(k, p.y, p.z);
    var x3 = fxa(k, q.y, q.z);
    t4 = fxm(k, t4, x3);
    x3 = fxa(k, t1, t2);
    t4 = fxs(k, t4, x3);
    x3 = fxa(k, p.x, p.z);
    var y3 = fxa(k, q.x, q.z);
    x3 = fxm(k, x3, y3);
    y3 = fxa(k, t0, t2);
    y3 = fxs(k, x3, y3);
    var z3 = fxm(k, k.b, t2);
    x3 = fxs(k, y3, z3);
    z3 = fxa(k, x3, x3);
    x3 = fxa(k, x3, z3);
    z3 = fxs(k, t1, x3);
    x3 = fxa(k, t1, x3);
    y3 = fxm(k, k.b, y3);
    t1 = fxa(k, t2, t2);
    t2 = fxa(k, t1, t2);
    y3 = fxs(k, y3, t2);
    y3 = fxs(k, y3, t0);
    t1 = fxa(k, y3, y3);
    y3 = fxa(k, t1, y3);
    t1 = fxa(k, t0, t0);
    t0 = fxa(k, t1, t0);
    t0 = fxs(k, t0, t2);
    t1 = fxm(k, t4, y3);
    t2 = fxm(k, t0, y3);
    y3 = fxm(k, x3, z3);
    y3 = fxa(k, y3, t2);
    x3 = fxm(k, t3, x3);
    x3 = fxs(k, x3, t1);
    z3 = fxm(k, t4, z3);
    t1 = fxm(k, t3, t0);
    z3 = fxa(k, z3, t1);
    return FPoint { x: x3, y: y3, z: z3 };
}

fn fx_add_any<T>(k: const FCurve<T>&, p: const FPoint<T>&, q: const FPoint<T>&) -> FPoint<T> {
    var t0 = fxm(k, p.x, q.x);
    var t1 = fxm(k, p.y, q.y);
    var t2 = fxm(k, p.z, q.z);
    var t3 = fxa(k, p.x, p.y);
    var t4 = fxa(k, q.x, q.y);
    t3 = fxm(k, t3, t4);
    t4 = fxa(k, t0, t1);
    t3 = fxs(k, t3, t4);                // X1 Y2 + X2 Y1
    t4 = fxa(k, p.x, p.z);
    var t5 = fxa(k, q.x, q.z);
    t4 = fxm(k, t4, t5);
    t5 = fxa(k, t0, t2);
    t4 = fxs(k, t4, t5);                // X1 Z2 + X2 Z1
    t5 = fxa(k, p.y, p.z);
    var x3 = fxa(k, q.y, q.z);
    t5 = fxm(k, t5, x3);
    x3 = fxa(k, t1, t2);
    t5 = fxs(k, t5, x3);                // Y1 Z2 + Y2 Z1
    var z3 = fxm(k, k.a, t4);
    x3 = fxm(k, k.b3, t2);
    z3 = fxa(k, x3, z3);
    x3 = fxs(k, t1, z3);
    z3 = fxa(k, t1, z3);
    var y3 = fxm(k, x3, z3);
    t1 = fxa(k, t0, t0);
    t1 = fxa(k, t1, t0);
    t2 = fxm(k, k.a, t2);
    t4 = fxm(k, k.b3, t4);
    t1 = fxa(k, t1, t2);
    t2 = fxs(k, t0, t2);
    t2 = fxm(k, k.a, t2);
    t4 = fxa(k, t4, t2);
    t0 = fxm(k, t1, t4);
    y3 = fxa(k, y3, t0);
    t0 = fxm(k, t5, t4);
    x3 = fxm(k, t3, x3);
    x3 = fxs(k, x3, t0);
    t0 = fxm(k, t3, t1);
    z3 = fxm(k, t5, z3);
    z3 = fxa(k, z3, t0);
    return FPoint { x: x3, y: y3, z: z3 };
}

fn fx_dbl_m3<T>(k: const FCurve<T>&, p: const FPoint<T>&) -> FPoint<T> {
    var t0 = fxm(k, p.x, p.x);
    var t1 = fxm(k, p.y, p.y);
    var t2 = fxm(k, p.z, p.z);
    var t3 = fxm(k, p.x, p.y);
    t3 = fxa(k, t3, t3);
    var z3 = fxm(k, p.x, p.z);
    z3 = fxa(k, z3, z3);
    var y3 = fxm(k, k.b, t2);
    y3 = fxs(k, y3, z3);
    var x3 = fxa(k, y3, y3);
    y3 = fxa(k, x3, y3);
    x3 = fxs(k, t1, y3);
    y3 = fxa(k, t1, y3);
    y3 = fxm(k, x3, y3);
    x3 = fxm(k, x3, t3);
    t3 = fxa(k, t2, t2);
    t2 = fxa(k, t2, t3);
    z3 = fxm(k, k.b, z3);
    z3 = fxs(k, z3, t2);
    z3 = fxs(k, z3, t0);
    t3 = fxa(k, z3, z3);
    z3 = fxa(k, z3, t3);
    t3 = fxa(k, t0, t0);
    t0 = fxa(k, t3, t0);
    t0 = fxs(k, t0, t2);
    t0 = fxm(k, t0, z3);
    y3 = fxa(k, y3, t0);
    t0 = fxm(k, p.y, p.z);
    t0 = fxa(k, t0, t0);
    z3 = fxm(k, t0, z3);
    x3 = fxs(k, x3, z3);
    z3 = fxm(k, t0, t1);
    z3 = fxa(k, z3, z3);
    z3 = fxa(k, z3, z3);
    return FPoint { x: x3, y: y3, z: z3 };
}

fn fx_dbl_any<T>(k: const FCurve<T>&, p: const FPoint<T>&) -> FPoint<T> {
    var t0 = fxm(k, p.x, p.x);
    var t1 = fxm(k, p.y, p.y);
    var t2 = fxm(k, p.z, p.z);
    var t3 = fxm(k, p.x, p.y);
    t3 = fxa(k, t3, t3);
    var z3 = fxm(k, p.x, p.z);
    z3 = fxa(k, z3, z3);
    var x3 = fxm(k, k.a, z3);
    var y3 = fxm(k, k.b3, t2);
    y3 = fxa(k, x3, y3);
    x3 = fxs(k, t1, y3);
    y3 = fxa(k, t1, y3);
    y3 = fxm(k, x3, y3);
    x3 = fxm(k, t3, x3);
    z3 = fxm(k, k.b3, z3);
    t2 = fxm(k, k.a, t2);
    t3 = fxs(k, t0, t2);
    t3 = fxm(k, k.a, t3);
    t3 = fxa(k, t3, z3);
    z3 = fxa(k, t0, t0);
    t0 = fxa(k, z3, t0);
    t0 = fxa(k, t0, t2);
    t0 = fxm(k, t0, t3);
    y3 = fxa(k, y3, t0);
    t2 = fxm(k, p.y, p.z);
    t2 = fxa(k, t2, t2);
    t0 = fxm(k, t2, t3);
    x3 = fxs(k, x3, t0);
    z3 = fxm(k, t2, t1);
    z3 = fxa(k, z3, z3);
    z3 = fxa(k, z3, z3);
    return FPoint { x: x3, y: y3, z: z3 };
}

// dst = src when mask is all ones.
fn fx_select<T>(dst: FPoint<T>&, src: const FPoint<T>&, mask: u32) {
    for i in dst.x.len {
        dst.x[i] = ct_select_u32(mask, src.x[i], dst.x[i]);
        dst.y[i] = ct_select_u32(mask, src.y[i], dst.y[i]);
        dst.z[i] = ct_select_u32(mask, src.z[i], dst.z[i]);
    }
}

// s * p: 4-bit windows over the full width of s, the table read by
// scanning, so the time depends on neither s nor p.
fn fx_mul<T>(k: const FCurve<T>&, s: const u32[:], p: const FPoint<T>&) -> FPoint<T> {
    var zero = k.one;
    for &x in zero { x = 0; }
    let inf = FPoint { x: zero, y: k.one, z: zero };
    var tab: FPoint<T>[16] = [inf; 16];
    tab[1] = p;
    for i in 2..16 { tab[i] = fx_add(k, tab[i - 1], p); }
    var acc = inf;
    var w = 8 * s.len;
    while w > 0 {
        w--;
        for j in 4 {
            let d = fx_dbl(k, acc);
            acc = d;
        }
        let win = exp_window(s, w);
        var sel = inf;
        for j in 16 { fx_select(sel, tab[j], ct_mask(ct_eq_u32(win, j as! u32))); }
        let sum = fx_add(k, acc, sel);
        acc = sum;
    }
    return acc;
}

// x^e mod m in normal form, for a public exponent e (p - 2 or n - 2):
// 4-bit windows, the table indexed by e's digits; r2 is R^2 mod m.
fn fx_pow<T>(x: const T&, e: const T&, m: const T&, m0i: u32, r2: const T&, mersenne: bool) -> T {
    var one = x;
    for &v in one { v = 0; }
    one[0] = 1;
    var xm = x;
    fx_mont(xm, x, r2, m, m0i, mersenne);
    var rm = x;
    fx_mont(rm, one, r2, m, m0i, mersenne);       // 1 in Montgomery form
    var tab: T[16] = [rm; 16];
    for i in 1..16 { fx_mont(tab[i], tab[i - 1], xm, m, m0i, mersenne); }
    var acc = rm;
    var w = 8 * e.len;
    while w > 0 {
        w--;
        for j in 4 {
            var t = acc;
            fx_mont(t, acc, acc, m, m0i, mersenne);
            acc = t;
        }
        var t = acc;
        fx_mont(t, acc, tab[exp_window(e[..], w)], m, m0i, mersenne);
        acc = t;
    }
    var r = acc;
    fx_mont(r, acc, one, m, m0i, mersenne);
    return r;
}

// a^(e) mod m at the curve's width, a and the result in normal form.
fn fx_inv(c: const Curve&, a: const u32[:], m: const u32[:], m0i: u32, r2: const u32[:],
          e: const u32[:], mersenne: bool) -> u32[..17] {
    var r = ec_zero(c);
    const for <N> in [7, 8, 12, 16, 17] {
        if c.nl == N {
            var x: u32[N] = [0; N];
            var ef = x;
            var mf = x;
            var r2f = x;
            fx_load(x, a);
            fx_load(ef, e);
            fx_load(mf, m);
            fx_load(r2f, r2);
            let v = fx_pow(x, ef, mf, m0i, r2f, mersenne);
            for i in N { r[i] = v[i]; }
        }
    }
    return r;
}

// Bit i of s.
fn ec_bit(s: const u32[:], i: i64) -> u32 { (s[i / 32] >> (i % 32) as! u32) & 1 }

// Column j of a comb with four teeth over s, d apart: bits j, j + d,
// j + 2d and j + 3d of s.
fn comb_digit(s: const u32[:], j: i64, d: i64) -> u32 {
    ec_bit(s, j) | ec_bit(s, j + d) << 1 | ec_bit(s, j + 2 * d) << 2 | ec_bit(s, j + 3 * d) << 3
}

// The comb's table: entry t is the sum of G, 2^d G, 2^2d G and 2^3d G for
// the bits of t.
fn fx_comb_table<T>(k: const FCurve<T>&, c: const Curve&, z: T) -> FPoint<T>[16] {
    var zero = k.one;
    for &x in zero { x = 0; }
    let inf = FPoint { x: zero, y: k.one, z: zero };
    var tab: FPoint<T>[16] = [inf; 16];
    var g = FPoint { x: z, y: z, z: k.one };
    fx_load(g.x, c.gx[..]);
    fx_load(g.y, c.gy[..]);
    tab[1] = g;
    for i in 3 {
        fx_load(g.x, c.cx[i][..]);
        fx_load(g.y, c.cy[i][..]);
        tab[2 << i] = g;
    }
    for t in 3..16 {
        let low = t & (0 - t);
        if t != low { tab[t] = fx_add(k, tab[t - low], tab[low]); }
    }
    return tab;
}

// s * G by the comb (Lim and Lee), d a quarter of s's width: d doublings
// and d additions, the table read by scanning, so the time does not
// depend on s.
fn fx_mul_base<T>(k: const FCurve<T>&, tab: const FPoint<T>[16]&, s: const u32[:]) -> FPoint<T> {
    let d = 8 * s.len;
    var acc = tab[0];
    var j = d;
    while j > 0 {
        j--;
        let dbl = fx_dbl(k, acc);
        acc = dbl;
        let col = comb_digit(s, j, d);
        var sel = tab[0];
        for t in 16 { fx_select(sel, tab[t], ct_mask(ct_eq_u32(col, t as! u32))); }
        let sum = fx_add(k, acc, sel);
        acc = sum;
    }
    return acc;
}

// u1 G + u2 q for public u1 and u2, as ECDSA verification needs, in
// variable time: the comb for u1, interleaved with sliding windows of up
// to five bits over u2 and the odd multiples q, 3q, ..., 31q.
fn fx_mul2_vartime<T>(k: const FCurve<T>&, tab: const FPoint<T>[16]&, u1: const u32[:], q: const FPoint<T>&,
              u2: const u32[:]) -> FPoint<T> {
    var odd: FPoint<T>[16] = [q; 16];
    let q2 = fx_dbl(k, q);
    for i in 1..16 { odd[i] = fx_add(k, odd[i - 1], q2); }
    // digit[j] = v (odd) where a window of u2 with value v ends at bit j.
    let bits = 32 * u2.len;
    var digit: u8[544] = [0; 544];
    var i = bits - 1;
    while i >= 0 {
        if ec_bit(u2, i) == 0 { i--; continue; }
        var j = if i >= 4 { i - 4 } else { 0 };
        while ec_bit(u2, j) == 0 { j++; }
        var v: u32 = 0;
        for b in j..i + 1 { v |= ec_bit(u2, b) << (b - j) as! u32; }
        digit[j] = v as! u8;
        i = j - 1;
    }
    let d = 8 * u1.len;
    var acc = tab[0];
    i = bits;
    while i > 0 {
        i--;
        let dbl = fx_dbl(k, acc);
        acc = dbl;
        if i < d {
            let col = comb_digit(u1, i, d);
            if col != 0 {
                let sum = fx_add(k, acc, tab[col]);
                acc = sum;
            }
        }
        if digit[i] != 0 {
            let sum = fx_add(k, acc, odd[(digit[i] - 1) / 2]);
            acc = sum;
        }
    }
    return acc;
}

// k * G for a scalar of the curve's width, in constant time.
fn ec_mul_base(c: const Curve&, k: const u32[:]) -> EcPoint {
    assert(k.len == c.nl);
    var r = ec_infinity(c);
    const for <N> in [7, 8, 12, 16, 17] {
        if c.nl == N {
            let z: u32[N] = [0; N];
            let fc = fx_curve(c, z);
            let tab = fx_comb_table(fc, c, z);
            let q = fx_mul_base(fc, tab, k);
            r = fx_store(c, q);
        }
    }
    return r;
}

// u1 G + u2 q, in variable time: for public scalars only.
fn ec_mul2_vartime(c: const Curve&, u1: const u32[:], q: const EcPoint&, u2: const u32[:]) -> EcPoint {
    assert(u1.len == c.nl && u2.len == c.nl);
    var r = ec_infinity(c);
    const for <N> in [7, 8, 12, 16, 17] {
        if c.nl == N {
            let z: u32[N] = [0; N];
            let fc = fx_curve(c, z);
            let tab = fx_comb_table(fc, c, z);
            let fq = fx_point(q, z);
            let pt = fx_mul2_vartime(fc, tab, u1, fq, u2);
            r = fx_store(c, pt);
        }
    }
    return r;
}

// k * p for a scalar of the curve's width, in constant time.
fn ec_mul(c: const Curve&, k: const u32[:], p: const EcPoint&) -> EcPoint {
    var r = ec_infinity(c);
    const for <N> in [7, 8, 12, 16, 17] {
        if c.nl == N {
            let z: u32[N] = [0; N];
            let fc = fx_curve(c, z);
            let fp = fx_point(p, z);
            let q = fx_mul(fc, k, fp);
            r = fx_store(c, q);
        }
    }
    return r;
}

// Affine x and y in normal form, and false for infinity.
fn ec_affine(c: const Curve&, p: const EcPoint&) -> u32[..17], u32[..17], bool {
    let z = from_mont(c, p.z[..]);
    let ok = ct_is_zero(z[..]) == 0;
    let zi = to_mont(c, finv(c, z[..])[..]);
    let x = from_mont(c, fmul(c, p.x[..], zi[..])[..]);
    let y = from_mont(c, fmul(c, p.y[..], zi[..])[..]);
    return x, y, ok;
}

// The uncompressed encoding 04 || x || y (SEC 1 §2.3.3), as TLS sends it.
fn ec_encode(c: const Curve&, p: const EcPoint&) -> u8[>..] {
    let x, y, ok = ec_affine(c, p);
    assert(ok);
    var out: u8[>..] = [];
    out.resize(1 + 2 * c.len, 0);
    out[0] = 4;
    be_from_limbs(out[1..1 + c.len], x[..]);
    be_from_limbs(out[1 + c.len..], y[..]);
    return out;
}

// x^3 + ax + b, for x in Montgomery form.
fn ec_rhs(c: const Curve&, xm: const u32[:]) -> u32[..17] {
    let x2 = fmul(c, xm, xm);
    let x3 = fmul(c, x2[..], xm);
    let ax = fmul(c, c.a[..], xm);
    return fadd(c, fadd(c, x3[..], ax[..])[..], c.b[..]);
}

// A point from its uncompressed encoding, checked to lie on the curve
// (which, with cofactor 1, also puts it in the group). Public data.
fn ec_decode(c: const Curve&, s: const u8[:]) -> EcPoint, bool {
    var p = ec_infinity(c);
    if s.len != 1 + 2 * c.len || s[0] != 4 { return p, false; }
    var x = ec_zero(c);
    var y = ec_zero(c);
    limbs_from_be(x[..], s[1..1 + c.len]);
    limbs_from_be(y[..], s[1 + c.len..]);
    if ct_lt(x[..], c.p[..]) == 0 || ct_lt(y[..], c.p[..]) == 0 { return p, false; }
    let xm = to_mont(c, x[..]);
    let ym = to_mont(c, y[..]);
    // y^2 == x^3 + ax + b
    let lhs = fmul(c, ym[..], ym[..]);
    let rhs = ec_rhs(c, xm[..]);
    if ct_eq(lhs[..], rhs[..]) == 0 { return p, false; }
    p.x = xm;
    p.y = ym;
    var one = ec_zero(c);
    one[0] = 1;
    p.z = to_mont(c, one[..]);
    return p, true;
}

// -p: (X : -Y : Z).
fn ec_neg(c: const Curve&, p: const EcPoint&) -> EcPoint {
    return EcPoint { x: p.x, y: fsub(c, ec_zero(c)[..], p.y[..]), z: p.z };
}

// The compressed encoding 02 or 03 (y's parity) || x (SEC 1 §2.3.3).
fn ec_encode_compressed(c: const Curve&, p: const EcPoint&) -> u8[>..] {
    let x, y, ok = ec_affine(c, p);
    assert(ok);
    var out: u8[>..] = [];
    out.resize(1 + c.len, 0);
    out[0] = 2 | ((y[0] & 1) as! u8);
    be_from_limbs(out[1..], x[..]);
    return out;
}

// A point from its compressed encoding (SEC 1 §2.3.4): y the square root
// of x^3 + ax + b of the parity asked, v^((p+1)/4) as p = 3 (mod 4) on
// P-256, P-384, P-521 and the three Brainpool curves (false on P-224,
// whose p is not). False for an x not below p or with no point. Public data.
fn ec_decode_compressed(c: const Curve&, s: const u8[:]) -> EcPoint, bool {
    var p = ec_infinity(c);
    if s.len != 1 + c.len || (s[0] != 2 && s[0] != 3) || c.p[0] & 3 != 3 { return p, false; }
    var x = ec_zero(c);
    limbs_from_be(x[..], s[1..]);
    if ct_lt(x[..], c.p[..]) == 0 { return p, false; }
    let xm = to_mont(c, x[..]);
    let rhs = ec_rhs(c, xm[..]);
    // (p + 1) / 4 = (p >> 2) + 1, as p = 3 (mod 4).
    var e = ec_zero(c);
    for i in c.nl {
        e[i] = c.p[i] >> 2;
        if i + 1 < c.nl { e[i] = e[i] | c.p[i + 1] << 30; }
    }
    var carry: u64 = 1;
    for i in c.nl {
        let t = e[i] + carry;
        e[i] = t as! u32;
        carry = t >> 32;
    }
    var y = ec_zero(c);
    mont_modexp(y[..], from_mont(c, rhs[..])[..], e[..], c.p[..], c.p0i, c.r2p[..]);
    var ym = to_mont(c, y[..]);
    if ct_eq(fmul(c, ym[..], ym[..])[..], rhs[..]) == 0 { return p, false; }
    if (y[0] & 1) != (s[0] & 1) { ym = fsub(c, ec_zero(c)[..], ym[..]); }
    p.x = xm;
    p.y = ym;
    var one = ec_zero(c);
    one[0] = 1;
    p.z = to_mont(c, one[..]);
    return p, true;
}

// A private scalar from its big-endian bytes; false unless 1 <= k < n.
fn ec_scalar(c: const Curve&, sk: const u8[:]) -> u32[..17], bool {
    var k = ec_zero(c);
    if sk.len != c.len { return k, false; }
    limbs_from_be(k[..], sk);
    let ok = (ct_lt(k[..], c.n[..]) & (ct_is_zero(k[..]) ^ 1)) == 1;
    return k, ok;
}

// The public key for a private key: 1 + 2 * len bytes.
fn ec_public_key(c: const Curve&, sk: const u8[:]) -> u8[>..] {
    let k, ok = ec_scalar(c, sk);
    assert(ok);
    let pt = ec_mul_base(c, k[..]);
    return ec_encode(c, pt);
}

// A fresh key pair from the OS's entropy: private (len bytes), public.
fn ec_keypair(c: const Curve&) -> u8[>..], u8[>..] {
    var sk: u8[>..] = [];
    sk.resize(c.len, 0);
    loop {
        entropy::random_bytes(sk);
        let k, ok = ec_scalar(c, sk);
        if ok { break; }
    }
    return sk, ec_public_key(c, sk);
}

// ECDH: the x-coordinate of sk * peer (len bytes), and false when the
// peer's key is not a valid point or the private key is out of range.
fn ecdh_shared(c: const Curve&, sk: const u8[:], peer: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let q, okq = ec_decode(c, peer);
    let k, okk = ec_scalar(c, sk);
    if !okq || !okk { return out, false; }
    let pt = ec_mul(c, k[..], q);
    let x, y, ok = ec_affine(c, pt);
    if !ok { return out, false; }
    out.resize(c.len, 0);
    be_from_limbs(out, x[..]);
    return out, true;
}

// The leftmost bits of a string, as many as the order has, as a scalar
// (bits2int of RFC 6979 §2.3.2).
fn ec_bits2int(c: const Curve&, h: const u8[:]) -> u32[..17] {
    var e = ec_zero(c);
    let nb = ::min(h.len, c.len);
    limbs_from_be(e[..], h[..nb]);
    let excess = 8 * nb - c.bits;
    if excess > 0 {
        let sh: u32 = excess as! u32;
        for i in c.nl {
            let hi: u32 = if i + 1 < c.nl { e[i + 1] << (32 - sh) } else { 0 };
            e[i] = (e[i] >> sh) | hi;
        }
    }
    return e;
}

// ECDSA signature of msg, hashed with the curve's hash: r || s, each len
// bytes. The nonce comes from HMAC-DRBG over the key and the hash (RFC
// 6979 §3.2), so signing needs no randomness and repeats exactly.
fn ecdsa_sign(c: const Curve&, sk: const u8[:], msg: const u8[:]) -> u8[>..] {
    let h = hash_bits(c.hash, msg);
    return ecdsa_sign_digest(c, sk, h, c.hash);
}

// ECDSA over a digest made by the hash `hash_id` (a bignum.hmac id), which
// RFC 6979's HMAC-DRBG then uses too. A digest of another length (a
// caller's own, as PKCS #11's CKM_ECDSA takes) is taken as bits2int
// takes any: its leftmost bits, as many as the order has.
fn ecdsa_sign_digest(c: const Curve&, sk: const u8[:], h: const u8[:], hash_id: i64) -> u8[>..] {
    let d, okd = ec_scalar(c, sk);
    assert(okd);
    assert(h.len > 0);
    let e = nreduce(c, ec_bits2int(c, h)[..]);
    let hl = hash_len(hash_id);
    var h1: u8[>..] = [];
    h1.resize(c.len, 0);
    be_from_limbs(h1, e[..]);
    var v: u8[>..] = [];
    v.resize(hl, 1);
    var k: u8[>..] = [];
    k.resize(hl, 0);
    var m: u8[>..] = [];
    for round in 2 {
        m.clear();
        m.append(v);
        m.push(round as! u8);
        m.append(sk);
        m.append(h1);
        let nk = hmac(hash_id, k, m);
        k = copy(nk);
        let nv = hmac(hash_id, k, v);
        v = copy(nv);
    }
    loop {
        // T: HMAC blocks until there are as many bits as the order has.
        var tt: u8[>..] = [];
        while tt.len < c.len {
            let nv = hmac(hash_id, k, v);
            v = copy(nv);
            tt.append(v);
        }
        let kk = ec_bits2int(c, tt);
        let okk = (ct_lt(kk[..], c.n[..]) & (ct_is_zero(kk[..]) ^ 1)) == 1;
        if okk {
            let kg = ec_mul_base(c, kk[..]);
            let x, y, ok = ec_affine(c, kg);
            let r = nreduce(c, x[..]);
            if ct_is_zero(r[..]) == 0 {
                let s = nmul(c, ninv(c, kk[..])[..], nadd(c, e[..], nmul(c, r[..], d[..])[..])[..]);
                if ct_is_zero(s[..]) == 0 {
                    var sig: u8[>..] = [];
                    sig.resize(2 * c.len, 0);
                    be_from_limbs(sig[..c.len], r[..]);
                    be_from_limbs(sig[c.len..], s[..]);
                    return sig;
                }
            }
        }
        m.clear();
        m.append(v);
        m.push(0);
        let nk = hmac(hash_id, k, m);
        k = copy(nk);
        let nv = hmac(hash_id, k, v);
        v = copy(nv);
    }
}

// Verifies an r || s signature on a digest made by any hash.
fn ecdsa_verify_digest(c: const Curve&, pk: const u8[:], digest: const u8[:], sig: const u8[:]) -> bool {
    if sig.len != 2 * c.len { return false; }
    let q, okq = ec_decode(c, pk);
    let r, okr = ec_scalar(c, sig[..c.len]);
    let s, oks = ec_scalar(c, sig[c.len..]);
    if !okq || !okr || !oks { return false; }
    let e = nreduce(c, ec_bits2int(c, digest)[..]);
    let w = ninv(c, s[..]);
    let u1 = nmul(c, e[..], w[..]);
    let u2 = nmul(c, r[..], w[..]);
    let pt = ec_mul2_vartime(c, u1[..], q, u2[..]);
    let x, y, ok = ec_affine(c, pt);
    if !ok { return false; }
    return ct_eq(nreduce(c, x[..])[..], r[..]) == 1;
}

// Verifies an r || s signature on msg, hashed with the curve's hash.
fn ecdsa_verify(c: const Curve&, pk: const u8[:], msg: const u8[:], sig: const u8[:]) -> bool {
    ecdsa_verify_digest(c, pk, hash_bits(c.hash, msg), sig)
}

// r || s as the DER SEQUENCE { INTEGER r, INTEGER s } of TLS and X.509.
fn der_uint(out: u8[>..]&, v: const u8[:]) {
    var i = 0;
    while i < v.len - 1 && v[i] == 0 { i++; }
    let lead0 = v[i] >= 0x80;
    out.push(2);
    out.push((v.len - i + (if lead0 { 1 } else { 0 })) as! u8);
    if lead0 { out.push(0); }
    out.append(v[i..]);
}

fn ecdsa_sig_to_der(raw: const u8[:]) -> u8[>..] {
    assert(raw.len % 2 == 0 && raw.len <= 132);
    let half = raw.len / 2;
    var body: u8[>..] = [];
    der_uint(body, raw[..half]);
    der_uint(body, raw[half..]);
    var out: u8[>..] = [];
    out.push(0x30);
    if body.len >= 128 { out.push(0x81); }      // P-521's and brainpoolP512r1's can pass 127 bytes
    out.push(body.len as! u8);
    out.append(body);
    return out;
}

// Reads one minimally encoded non-negative INTEGER of at most len bytes
// into out (right-aligned); returns the offset after it, or -1.
fn der_read_uint(der: const u8[:], at: i64, out: u8[:]) -> i64 {
    if at + 2 > der.len || der[at] != 2 { return -1; }
    let n: i64 = der[at + 1];
    let start = at + 2;
    if n == 0 || n >= 128 || start + n > der.len { return -1; }
    if der[start] >= 0x80 { return -1; }                         // negative
    if n > 1 && der[start] == 0 && der[start + 1] < 0x80 { return -1; }   // not minimal
    var v = der[start..start + n];
    if v.len > 1 && v[0] == 0 { v = v[1..]; }
    if v.len > out.len { return -1; }
    for i in out.len { out[i] = 0; }
    for i in v.len { out[out.len - v.len + i] = v[i]; }
    return start + n;
}

// A DER signature back to r || s of 2 * len bytes; strict, so a signature
// has exactly one accepted encoding.
fn ecdsa_sig_from_der(c: const Curve&, der: const u8[:]) -> u8[>..], bool {
    let raw, ok = sig_from_der(c.len, der);
    return raw, ok;
}

// The same for any width of r and s.
fn sig_from_der(len: i64, der: const u8[:]) -> u8[>..], bool {
    var raw: u8[>..] = [];
    raw.resize(2 * len, 0);
    // The SEQUENCE's length in the short form, or 0x81 and a byte >= 128.
    var hdr = 2;
    var ok = der.len >= 2 && der[0] == 0x30;
    if ok && der[1] == 0x81 {
        ok = der.len >= 3 && der[2] >= 128 && der[2] as i64 + 3 == der.len;
        hdr = 3;
    } else if ok {
        ok = der[1] < 128 && der[1] as i64 + 2 == der.len;
    }
    if ok {
        let mid = der_read_uint(der, hdr, raw[..len]);
        ok = mid >= 0 && der_read_uint(der, mid, raw[len..]) == der.len;
    }
    if !ok { raw.clear(); }
    return raw, ok;
}
