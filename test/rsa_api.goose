// bignum.rsa's API: generated keys, the checks made when loading a key,
// the raw operations' input checks, and signatures and ciphertexts that
// must not verify or decrypt under another key.
import std;
import bignum from "..";
import bignum.rsa;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn main() {
    let key = bignum::rsa_generate(1024);
    let pub = bignum::rsa_public(key);
    check("bits", bignum::rsa_bits(key) == 1024 && bignum::rsa_size(pub) == 128);
    let n = bignum::big_of(key.n);
    let e = bignum::big_of(key.e);
    let d = bignum::big_of(key.d);
    let p = bignum::big_of(key.p);
    let q = bignum::big_of(key.q);
    check("e", bignum::cmp_i64(e, 65537) == 0);
    check("n = pq", bignum::eq(bignum::mul(p, q), n) && bignum::gt(p, q));
    check("primes of 512 bits", bignum::bit_len(p) == 512 && bignum::bit_len(q) == 512);
    let x = bignum::from_u64(123456789);
    check("e d", bignum::eq(bignum::modpow(bignum::modpow(x, e, n), d, n), x));

    // A key loads back from its numbers, and bad numbers are refused.
    let k2, ok2 = bignum::rsa_key_from(n, e, d, p, q);
    check("reload", ok2 && k2.dp == key.dp && k2.qinv == key.qinv);
    let k3, ok3 = bignum::rsa_key_from(n, e, d, p, bignum::add(q, bignum::big(2)));
    check("p q != n", !ok3);
    let k4, ok4 = bignum::rsa_key_from(n, e, bignum::add(d, bignum::big(2)), p, q);
    check("wrong d", !ok4);
    let k5, ok5 = bignum::rsa_key_from(n, bignum::big(65536), d, p, q);
    check("even e", !ok5);
    let p5, okp5 = bignum::rsa_public_from(bignum::sub(bignum::shl(bignum::one(), 511), bignum::one()), e);
    check("too small", !okp5);
    let p6, okp6 = bignum::rsa_public_from(n, n);
    check("e >= n", !okp6);
    let p7, okp7 = bignum::rsa_public_from(n, e);
    check("public from", okp7 && p7.n == pub.n && p7.e == pub.e);

    // Raw operations: k bytes below n, and they invert each other.
    var m: u8[>..] = [];
    m.resize(128, 0);
    m[127] = 42;
    let c, okc = bignum::rsa_public_op(pub, m);
    let m2, okm = bignum::rsa_private_op(key, c);
    check("raw round trip", okc && okm && m2 == m);
    let nb = bignum::to_bytes_be(n, 128);
    let r1, okr1 = bignum::rsa_public_op(pub, nb);
    check("public op x = n", !okr1);
    let r2, okr2 = bignum::rsa_private_op(key, nb);
    check("private op x = n", !okr2);
    let r3, okr3 = bignum::rsa_private_op(key, m[1..]);
    check("private op short", !okr3);
    var zero: u8[>..] = [];
    zero.resize(128, 0);
    let r4, okr4 = bignum::rsa_private_op(key, zero);
    check("private op 0", okr4 && r4 == zero);

    // Signatures and ciphertexts are bound to their key.
    let other = bignum::rsa_generate(1024);
    let s1 = bignum::rsa_sign_pkcs1(key, "message");
    let s2 = bignum::rsa_sign_pss(key, "message");
    check("pkcs1", bignum::rsa_verify_pkcs1(pub, "message", s1));
    check("pss", bignum::rsa_verify_pss(key, "message", s2));
    check("pkcs1 other key", !bignum::rsa_verify_pkcs1(other, "message", s1));
    check("pss other key", !bignum::rsa_verify_pss(other, "message", s2));
    check("pkcs1 is not pss", !bignum::rsa_verify_pss(pub, "message", s1));
    let biggest = bignum::rsa_oaep_max(pub);
    check("oaep max", biggest == 62);
    var long: u8[>..] = [];
    long.resize(biggest, 7);
    let ct = bignum::rsa_encrypt_oaep(pub, long, "label");
    let back, okb = bignum::rsa_decrypt_oaep(key, ct, "label");
    check("oaep longest", okb && back == long);
    let none, okn = bignum::rsa_decrypt_oaep(other, ct, "label");
    check("oaep other key", !okn && none.len == 0);
    // A valid RSA input that is not an OAEP block.
    let s3, oks3 = bignum::rsa_public_op(pub, m);
    let junk, okj = bignum::rsa_decrypt_oaep(key, s3);
    check("oaep junk", oks3 && !okj);

    print("rsa api: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
