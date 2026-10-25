// bigman.rsa's API: generated keys, the checks made when loading a key,
// the raw operations' input checks, and signatures and ciphertexts that
// must not verify or decrypt under another key.
import std;
import bigman from "..";
import bigman.rsa;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn main() {
    let key = bigman::rsa_generate(1024);
    let pub = bigman::rsa_public(key);
    check("bits", bigman::rsa_bits(key) == 1024 && bigman::rsa_size(pub) == 128);
    let n = bigman::big_of(key.n);
    let e = bigman::big_of(key.e);
    let d = bigman::big_of(key.d);
    let p = bigman::big_of(key.p);
    let q = bigman::big_of(key.q);
    check("e", bigman::cmp_i64(e, 65537) == 0);
    check("n = pq", bigman::eq(bigman::mul(p, q), n) && bigman::gt(p, q));
    check("primes of 512 bits", bigman::bit_len(p) == 512 && bigman::bit_len(q) == 512);
    let x = bigman::from_u64(123456789);
    check("e d", bigman::eq(bigman::modpow(bigman::modpow(x, e, n), d, n), x));

    // A key loads back from its numbers, and bad numbers are refused.
    let k2, ok2 = bigman::rsa_key_from(n, e, d, p, q);
    check("reload", ok2 && k2.dp == key.dp && k2.qinv == key.qinv);
    let k3, ok3 = bigman::rsa_key_from(n, e, d, p, bigman::add(q, bigman::big(2)));
    check("p q != n", !ok3);
    let k4, ok4 = bigman::rsa_key_from(n, e, bigman::add(d, bigman::big(2)), p, q);
    check("wrong d", !ok4);
    let k5, ok5 = bigman::rsa_key_from(n, bigman::big(65536), d, p, q);
    check("even e", !ok5);
    let p5, okp5 = bigman::rsa_public_from(bigman::sub(bigman::shl(bigman::one(), 511), bigman::one()), e);
    check("too small", !okp5);
    let p6, okp6 = bigman::rsa_public_from(n, n);
    check("e >= n", !okp6);
    let p7, okp7 = bigman::rsa_public_from(n, e);
    check("public from", okp7 && p7.n == pub.n && p7.e == pub.e);

    // Raw operations: k bytes below n, and they invert each other.
    var m: u8[>..] = [];
    m.resize(128, 0);
    m[127] = 42;
    let c, okc = bigman::rsa_public_op(pub, m);
    let m2, okm = bigman::rsa_private_op(key, c);
    check("raw round trip", okc && okm && m2 == m);
    let nb = bigman::to_bytes_be(n, 128);
    let r1, okr1 = bigman::rsa_public_op(pub, nb);
    check("public op x = n", !okr1);
    let r2, okr2 = bigman::rsa_private_op(key, nb);
    check("private op x = n", !okr2);
    let r3, okr3 = bigman::rsa_private_op(key, m[1..]);
    check("private op short", !okr3);
    var zero: u8[>..] = [];
    zero.resize(128, 0);
    let r4, okr4 = bigman::rsa_private_op(key, zero);
    check("private op 0", okr4 && r4 == zero);

    // Signatures and ciphertexts are bound to their key.
    let other = bigman::rsa_generate(1024);
    let s1 = bigman::rsa_sign_pkcs1(key, "message");
    let s2 = bigman::rsa_sign_pss(key, "message");
    check("pkcs1", bigman::rsa_verify_pkcs1(pub, "message", s1));
    check("pss", bigman::rsa_verify_pss(key, "message", s2));
    check("pkcs1 other key", !bigman::rsa_verify_pkcs1(other, "message", s1));
    check("pss other key", !bigman::rsa_verify_pss(other, "message", s2));
    check("pkcs1 is not pss", !bigman::rsa_verify_pss(pub, "message", s1));
    let biggest = bigman::rsa_oaep_max(pub);
    check("oaep max", biggest == 62);
    var long: u8[>..] = [];
    long.resize(biggest, 7);
    let ct = bigman::rsa_encrypt_oaep(pub, long, "label");
    let back, okb = bigman::rsa_decrypt_oaep(key, ct, "label");
    check("oaep longest", okb && back == long);
    let none, okn = bigman::rsa_decrypt_oaep(other, ct, "label");
    check("oaep other key", !okn && none.len == 0);
    // A valid RSA input that is not an OAEP block.
    let s3, oks3 = bigman::rsa_public_op(pub, m);
    let junk, okj = bigman::rsa_decrypt_oaep(key, s3);
    check("oaep junk", oks3 && !okj);

    print("rsa api: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
