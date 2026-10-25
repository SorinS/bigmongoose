// bignum.rsa: RSA (RFC 8017): key generation, PKCS #1 v1.5 and PSS
// signatures with SHA-256, SHA-384 or SHA-512, and OAEP encryption with
// SHA-256. Keys up to 4096 bits.
//
// The private-key operation is constant time: CRT with Montgomery
// exponentiation from bignum.mont over limbs of the key's width, the
// reductions done bit by bit, the input blinded by a random r^e, and the
// result checked against the public key before it is released (a fault in
// one CRT half would otherwise give the key away). Public-key operations
// use BigInt, as nothing in them is secret. Key generation and key loading
// use BigInt on the primes too, so they are not constant time.

namespace bignum;

import std;
import bignum;
import ct;
import mont;
import sha256;
import hmac;
import entropy;

// Little-endian limbs, normalized: n, p and q have no zero top limb, and
// each exponent and qinv is padded to its modulus' width (d to n's, dp and
// qinv to p's, dq to q's), so lengths say nothing more than the key size.
struct RsaPublicKey { n: u32[..128], e: u32[..128] }

struct RsaPrivateKey {
    n: u32[..128], e: u32[..128], d: u32[..128],
    p: u32[..64], q: u32[..64], dp: u32[..64], dq: u32[..64], qinv: u32[..64],
}

// DER of each hash's AlgorithmIdentifier and digest header (RFC 8017 §9.2).
let SHA256_DIGEST_INFO: u8[19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20,
];
let SHA384_DIGEST_INFO: u8[19] = [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
    0x05, 0x00, 0x04, 0x30,
];
let SHA512_DIGEST_INFO: u8[19] = [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
    0x05, 0x00, 0x04, 0x40,
];

// dst = the limbs of v >= 0, exactly w of them.
fn set_limbs<A>(dst: A&, v, w: i64) {
    assert(v.mag.len <= w);
    dst.clear();
    for i in w { dst.push(if i < v.mag.len { v.mag[i] } else { 0 }); }
}

fn zero_limbs(n: i64) -> u32[>..] {
    var r: u32[>..] = [];
    r.resize(n, 0);
    return r;
}

// The modulus size in bits, and in bytes (the size of every signature
// and ciphertext).
fn rsa_bits(key) -> i64 { mag_bit_len(key.n) }
fn rsa_size(key) -> i64 { (rsa_bits(key) + 7) / 8 }

fn mag_bit_len(xs) -> i64 {
    if xs.len == 0 { return 0; }
    return 32 * xs.len - ::clz(xs[xs.len - 1] as u64) + 32;
}

fn rsa_public(key) -> RsaPublicKey {
    var r = RsaPublicKey { n: [], e: [] };
    for x in key.n { r.n.push(x); }
    for x in key.e { r.e.push(x); }
    return r;
}

// A public key from its numbers; false unless n is odd, 512 to 4096 bits,
// and 1 < e < n is odd.
fn rsa_public_from(n, e) -> RsaPublicKey, bool {
    var r = RsaPublicKey { n: [], e: [] };
    let bits = bit_len(n);
    if n.neg || e.neg || bits < 512 || bits > 4096 || !is_odd(n) || !is_odd(e)
        || cmp_i64(e, 1) <= 0 || ge(e, n) {
        return r, false;
    }
    set_limbs(r.n, n, n.mag.len);
    set_limbs(r.e, e, e.mag.len);
    return r, true;
}

// A private key from n, e, d, p and q, with the CRT values derived and the
// whole checked for consistency.
fn rsa_key_from(n, e, d, p, q) -> RsaPrivateKey, bool {
    var k = RsaPrivateKey { n: [], e: [], d: [], p: [], q: [], dp: [], dq: [], qinv: [] };
    let pub, ok = rsa_public_from(n, e);
    if !ok || p.neg || q.neg || d.neg || !is_odd(p) || !is_odd(q) || cmp_i64(p, 1) <= 0
        || cmp_i64(q, 1) <= 0 || !eq(mul(p, q), n) || p.mag.len > 64 || q.mag.len > 64
        || ge(d, n) {
        return k, false;
    }
    let p1 = sub(p, one());
    let q1 = sub(q, one());
    let dp = mod_floor(d, p1);
    let dq = mod_floor(d, q1);
    let qinv, inv_ok = modinv(q, p);
    if !inv_ok || !eq(mod_floor(mul(e, dp), p1), one()) || !eq(mod_floor(mul(e, dq), q1), one()) {
        return k, false;
    }
    for x in pub.n { k.n.push(x); }
    for x in pub.e { k.e.push(x); }
    set_limbs(k.d, d, n.mag.len);
    set_limbs(k.p, p, p.mag.len);
    set_limbs(k.q, q, q.mag.len);
    set_limbs(k.dp, dp, p.mag.len);
    set_limbs(k.dq, dq, q.mag.len);
    set_limbs(k.qinv, qinv, p.mag.len);
    return k, true;
}

// a mod d for a small d.
fn limbs_mod_small(a: const u32[:], d: u32) -> u32 {
    var r: u64 = 0;
    var i = a.len;
    while i > 0 {
        i--;
        r = ((r << 32) | a[i]) % d;
    }
    return r as! u32;
}

// The odd primes below 2000, for trial division.
fn small_primes() -> u32[>..] {
    var sieve: bool[2000] = [true; 2000];
    var out: u32[>..] = [];
    for i in 3..2000 {
        if !sieve[i] { continue; }
        if i % 2 == 0 { continue; }
        out.push(i as! u32);
        var j = i * i;
        while j < 2000 { sieve[j] = false; j += i; }
    }
    return out;
}

// A uniform random integer in [0, 2^bits).
fn random_bits(bits: i64) -> BigInt {
    var b: u8[>..] = [];
    b.resize((bits + 7) / 8, 0);
    random_bytes(b);
    let extra = 8 * b.len - bits;
    if extra > 0 { b[0] = b[0] & (255 >> extra) as! u8; }
    return from_bytes_be(b);
}

// A uniform random integer in [lo, hi), for lo < hi.
fn random_range(lo, hi) -> BigInt {
    let span = sub(hi, lo);
    let bits = bit_len(span);
    loop {
        let r = random_bits(bits);
        if lt(r, span) { return add(r, lo); }
    }
}

// Miller-Rabin with `rounds` random bases, for odd p > 3.
fn miller_rabin(p, rounds: i64) -> bool {
    let n = p.mag.len;
    let m = p.mag;
    let m0i = mont_m0i(m[0]);
    var r2 = zero_limbs(n);
    mont_r2(r2, m);
    let p1 = sub(p, one());
    var s = 0;
    while !test_bit(p1, s) { s++; }
    let dexp = shr(p1, s);
    var minus1 = zero_limbs(n);
    for i in p1.mag.len { minus1[i] = p1.mag[i]; }
    var one_l = zero_limbs(n);
    one_l[0] = 1;
    var x = zero_limbs(n);
    var a = zero_limbs(n);
    var t = zero_limbs(n + 2);
    var tmp = zero_limbs(n);
    for round in rounds {
        let base = random_range(big(2), p1);
        for i in n { a[i] = if i < base.mag.len { base.mag[i] } else { 0 }; }
        mont_modexp(x, a, dexp.mag, m, m0i, r2);
        if ct_eq(x, one_l) == 1 || ct_eq(x, minus1) == 1 { continue; }
        var witness = true;
        for i in s - 1 {
            mont_mul(tmp, x, x, m, m0i, t);              // x^2 / R
            mont_mul(x, tmp, r2, m, m0i, t);             // x^2
            if ct_eq(x, minus1) == 1 { witness = false; break; }
        }
        if witness { return false; }
    }
    return true;
}

// A random prime of exactly `bits` bits with its top two bits set (so a
// product of two has twice the bits) and gcd(p - 1, e) == 1.
fn rsa_random_prime(bits: i64, e, primes: const u32[:]) -> BigInt {
    let rounds = if bits >= 1024 { 5 } else if bits >= 512 { 8 } else { 40 };
    loop {
        let p = bit_or(random_bits(bits), add(shl(big(3), bits - 2), one()));
        var sieved = true;
        for sp in primes {
            if limbs_mod_small(p.mag, sp) == 0 { sieved = false; break; }
        }
        if !sieved { continue; }
        if !eq(gcd(sub(p, one()), e), one()) { continue; }
        if miller_rabin(p, rounds) { return p; }
    }
}

// A new key of `bits` bits (a multiple of 64, 1024 to 4096) with public
// exponent e (65537 unless given), from the OS's entropy.
fn rsa_generate(bits: i64, e: u64 = 65537) -> RsaPrivateKey {
    assert(bits % 64 == 0 && bits >= 1024 && bits <= 4096);
    assert(e >= 3 && e % 2 == 1);
    let eb = from_u64(e);
    let primes = small_primes();
    loop {
        let p = rsa_random_prime(bits / 2, eb, primes);
        let q = rsa_random_prime(bits / 2, eb, primes);
        if eq(p, q) { continue; }
        let n = mul(p, q);
        let lambda = lcm(sub(p, one()), sub(q, one()));
        let d, ok = modinv(eb, lambda);
        if !ok { continue; }
        // p > q is the usual order, so qinv = q^-1 mod p.
        if gt(p, q) {
            let k, kok = rsa_key_from(n, eb, d, p, q);
            if kok { return k; }
        } else {
            let k, kok = rsa_key_from(n, eb, d, q, p);
            if kok { return k; }
        }
    }
}

// out = c^d mod n for c < n, both at n's width, in constant time.
fn rsa_private_limbs(key, out: u32[:], c: const u32[:]) {
    let nl = key.n.len;
    let pl = key.p.len;
    let ql = key.q.len;
    let n = key.n[..];
    let p = key.p[..];
    let q = key.q[..];
    let n0i = mont_m0i(n[0]);
    let p0i = mont_m0i(p[0]);
    let q0i = mont_m0i(q[0]);
    var r2n = zero_limbs(nl);
    var r2p = zero_limbs(pl);
    var r2q = zero_limbs(ql);
    mont_r2(r2n, n);
    mont_r2(r2p, p);
    mont_r2(r2q, q);
    var tn = zero_limbs(nl + 2);
    var tp = zero_limbs(pl + 2);

    // Blinding: cb = c * r^e mod n for a random r, undone with 1/r at the
    // end. modinv runs in variable time, on r alone.
    let nb = big_of(n);
    var r = zero();
    var rinv = zero();
    loop {
        r = random_range(one(), nb);
        let ri, ok = modinv(r, nb);
        if ok { rinv = copy(ri); break; }
    }
    var rl = zero_limbs(nl);
    var rinvl = zero_limbs(nl);
    for i in r.mag.len { rl[i] = r.mag[i]; }
    for i in rinv.mag.len { rinvl[i] = rinv.mag[i]; }
    var re = zero_limbs(nl);
    mont_modexp(re, rl, key.e[..], n, n0i, r2n);
    var tmp = zero_limbs(nl);
    var cb = zero_limbs(nl);
    mont_mul(tmp, c, re, n, n0i, tn);
    mont_mul(cb, tmp, r2n, n, n0i, tn);

    // The two halves.
    var cp = zero_limbs(pl);
    var m1 = zero_limbs(pl);
    ct_reduce(cp, cb, p);
    mont_modexp(m1, cp, key.dp[..], p, p0i, r2p);
    var cq = zero_limbs(ql);
    var m2 = zero_limbs(ql);
    ct_reduce(cq, cb, q);
    mont_modexp(m2, cq, key.dq[..], q, q0i, r2q);

    // Garner: h = qinv (m1 - m2) mod p, m = m2 + h q.
    var m2p = zero_limbs(pl);
    ct_reduce(m2p, m2, p);
    var diff = zero_limbs(pl);
    ct_mod_sub(diff, m1, m2p, p);
    var tp1 = zero_limbs(pl);
    var h = zero_limbs(pl);
    mont_mul(tp1, key.qinv[..], diff, p, p0i, tp);
    mont_mul(h, tp1, r2p, p, p0i, tp);
    var prod = zero_limbs(pl + ql);
    ct_mul(prod, h, q);
    var carry: u64 = 0;
    for i in pl + ql {
        let x: u64 = prod[i];
        let t = x + (if i < ql { m2[i] } else { 0 }) + carry;
        prod[i] = t as! u32;
        carry = t >> 32;
    }
    // prod < n, so it fits n's width.
    var mb = zero_limbs(nl);
    for i in nl { mb[i] = prod[i]; }

    // Unblind, then check m^e == c before letting m out.
    mont_mul(tmp, mb, rinvl, n, n0i, tn);
    mont_mul(out, tmp, r2n, n, n0i, tn);
    var check = zero_limbs(nl);
    mont_modexp(check, out, key.e[..], n, n0i, r2n);
    assert(ct_eq(check, c) == 1);                        // a fault: never release out
}

// The raw RSA functions on k-byte big-endian strings (k = rsa_size): x^e
// and x^d mod n. False when x is not k bytes or not below n.
fn rsa_public_op(key, x: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if x.len != rsa_size(key) { return out, false; }
    let xb = from_bytes_be(x);
    let nb = big_of(key.n);
    if ge(xb, nb) { return out, false; }
    let y = modpow(xb, big_of(key.e), nb);
    out = to_bytes_be(y, x.len);
    return out, true;
}

fn rsa_private_op(key: const RsaPrivateKey&, x: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let nl = key.n.len;
    if x.len != rsa_size(key) { return out, false; }
    var c = zero_limbs(nl);
    limbs_from_be(c, x);
    if ct_lt(c, key.n[..]) == 0 { return out, false; }  // public: x is the input
    var m = zero_limbs(nl);
    rsa_private_limbs(key, m, c);
    out.resize(x.len, 0);
    be_from_limbs(out, m);
    return out, true;
}

// Signatures hash with SHA-256, SHA-384 or SHA-512: `hash` is 256, 384
// or 512, as in bignum.hmac.

// PKCS #1 v1.5 signatures (RSASSA-PKCS1-v1_5).
fn pkcs1_encode(em: u8[:], bits: i64, digest: const u8[:]) {
    let di = if bits == 256 { SHA256_DIGEST_INFO } else if bits == 384 { SHA384_DIGEST_INFO } else { SHA512_DIGEST_INFO };
    assert(digest.len == bits / 8);
    let tlen = di.len + digest.len;
    assert(em.len >= tlen + 11);
    em[0] = 0;
    em[1] = 1;
    let ps = em.len - tlen - 3;
    for i in ps { em[2 + i] = 0xff; }
    em[2 + ps] = 0;
    for i in di.len { em[3 + ps + i] = di[i]; }
    for i in digest.len { em[3 + ps + di.len + i] = digest[i]; }
}

fn rsa_sign_pkcs1(key: const RsaPrivateKey&, msg: const u8[:], hash: i64 = 256) -> u8[>..] {
    var em: u8[>..] = [];
    em.resize(rsa_size(key), 0);
    pkcs1_encode(em, hash, hash_bits(hash, msg));
    let s, ok = rsa_private_op(key, em);
    assert(ok);
    return s;
}

// The encoding is rebuilt and compared whole, rather than parsed.
fn rsa_verify_pkcs1(key, msg: const u8[:], sig: const u8[:], hash: i64 = 256) -> bool {
    let m, ok = rsa_public_op(key, sig);
    if !ok || m.len < hash / 8 + 30 { return false; }
    var em: u8[>..] = [];
    em.resize(m.len, 0);
    pkcs1_encode(em, hash, hash_bits(hash, msg));
    return ct_eq_bytes(em, m) == 1;
}

// PSS with MGF1 over the same hash (RSASSA-PSS). The salt is as long as
// the hash unless salt_len says otherwise; TLS 1.3 requires that length.

// H = Hash(0^8 || mhash || salt)
fn pss_hash(bits: i64, mhash: const u8[:], salt: const u8[:]) -> u8[>..] {
    let z: u8[8] = [0; 8];
    var m: u8[>..] = [];
    m.append(z);
    m.append(mhash);
    m.append(salt);
    return hash_bits(bits, m);
}

fn rsa_sign_pss_with_salt(key: const RsaPrivateKey&, msg: const u8[:], salt: const u8[:],
                          hash: i64 = 256) -> u8[>..] {
    let hl = hash / 8;
    let k = rsa_size(key);
    let embits = rsa_bits(key) - 1;
    let emlen = (embits + 7) / 8;
    assert(emlen >= hl + salt.len + 2);
    let h = pss_hash(hash, hash_bits(hash, msg), salt);
    // em holds EM right-aligned: one leading zero byte when emlen < k.
    var em: u8[>..] = [];
    em.resize(k, 0);
    let off = k - emlen;
    let dblen = emlen - hl - 1;
    let db = em[off..off + dblen];
    db[dblen - salt.len - 1] = 1;
    for i in salt.len { db[dblen - salt.len + i] = salt[i]; }
    mgf1(hash, db, h);
    db[0] = db[0] & (255 >> (8 * emlen - embits)) as! u8;
    for i in hl { em[off + dblen + i] = h[i]; }
    em[k - 1] = 0xbc;
    let s, ok = rsa_private_op(key, em);
    assert(ok);
    return s;
}

fn rsa_sign_pss(key: const RsaPrivateKey&, msg: const u8[:], salt_len: i64 = -1, hash: i64 = 256) -> u8[>..] {
    var salt: u8[>..] = [];
    salt.resize(if salt_len < 0 { hash / 8 } else { salt_len }, 0);
    random_bytes(salt);
    return rsa_sign_pss_with_salt(key, msg, salt, hash);
}

fn rsa_verify_pss(key, msg: const u8[:], sig: const u8[:], salt_len: i64 = -1, hash: i64 = 256) -> bool {
    let hl = hash / 8;
    let slen = if salt_len < 0 { hl } else { salt_len };
    let m, ok = rsa_public_op(key, sig);
    if !ok { return false; }
    let k = m.len;
    let embits = rsa_bits(key) - 1;
    let emlen = (embits + 7) / 8;
    if emlen < hl + slen + 2 { return false; }
    let off = k - emlen;
    if off > 0 && m[0] != 0 { return false; }
    if m[k - 1] != 0xbc { return false; }
    let dblen = emlen - hl - 1;
    let zbits = 8 * emlen - embits;
    let top = (255 << (8 - zbits)) & 255;
    if m[off] & top != 0 { return false; }
    var db: u8[>..] = [];
    db.append(m[off..off + dblen]);
    let h = m[off + dblen..off + dblen + hl];
    mgf1(hash, db, h);
    db[0] = db[0] & (255 >> zbits) as! u8;
    let ps = dblen - slen - 1;
    for i in ps { if db[i] != 0 { return false; } }
    if db[ps] != 1 { return false; }
    let h2 = pss_hash(hash, hash_bits(hash, msg), db[ps + 1..]);
    return ct_eq_bytes(h2, h) == 1;
}

// OAEP with SHA-256 and MGF1-SHA-256 (RSAES-OAEP). A message takes at most
// rsa_size(key) - 66 bytes.
fn rsa_oaep_max(key) -> i64 { rsa_size(key) - 66 }

fn rsa_encrypt_oaep_with_seed(key, msg: const u8[:], label: const u8[:], seed: const u8[:]) -> u8[>..] {
    let k = rsa_size(key);
    assert(msg.len <= k - 66 && seed.len == 32);
    var em: u8[>..] = [];
    em.resize(k, 0);
    let lhash = sha256(label);
    let dblen = k - 33;
    let db = em[33..];
    for i in 32 { db[i] = lhash[i]; }
    db[dblen - msg.len - 1] = 1;
    for i in msg.len { db[dblen - msg.len + i] = msg[i]; }
    let sd = em[1..33];
    for i in 32 { sd[i] = seed[i]; }
    mgf1_xor(db, sd);
    mgf1_xor(sd, db);
    let c, ok = rsa_public_op(key, em);
    assert(ok);
    return c;
}

fn rsa_encrypt_oaep(key, msg: const u8[:], label: const u8[:] = "") -> u8[>..] {
    var seed: u8[32] = [0; 32];
    random_bytes(seed);
    return rsa_encrypt_oaep_with_seed(key, msg, label, seed);
}

// The message and true, or empty and false. Every check on the decoded
// block is made in constant time and folded into one flag, so a failure
// does not say which part was wrong (Manger's attack).
fn rsa_decrypt_oaep(key: const RsaPrivateKey&, ct: const u8[:], label: const u8[:] = "") -> u8[>..], bool {
    var out: u8[>..] = [];
    let k = rsa_size(key);
    if k < 66 { return out, false; }
    var em, ok = rsa_private_op(key, ct);
    if !ok { return out, false; }
    let dblen = k - 33;
    let sd = em[1..33];
    let db = em[33..];
    mgf1_xor(sd, db);
    mgf1_xor(db, sd);
    let lhash = sha256(label);
    var good = ct_is_zero_u32(em[0]) & ct_eq_bytes(db[..32], lhash);
    // Find the 0x01 after the zero padding, without branching on bytes.
    var found: u32 = 0;
    var bad: u32 = 0;
    var start: u32 = 0;
    for i in 32..dblen {
        let b: u32 = db[i];
        let is1 = ct_eq_u32(b, 1) & (found ^ 1);
        let is0 = ct_is_zero_u32(b);
        bad = bad | ((found ^ 1) & (is0 ^ 1) & (is1 ^ 1));
        start = ct_select_u32(ct_mask(is1), (i + 1) as! u32, start);
        found = found | is1;
    }
    good = good & found & (bad ^ 1);
    if good == 0 { return out, false; }
    let from: i64 = start;
    out.append(db[from..]);
    return out, true;
}
