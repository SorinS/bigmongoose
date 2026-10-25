// bigman.hmac: HMAC (RFC 2104) and HKDF (RFC 5869) over SHA-256, SHA-384
// and SHA-512, the key derivation of TLS 1.3. `bits` picks the hash: 256,
// 384 or 512.

namespace bigman;

import std;
import sha256;
import sha512;

fn hash_len(bits: i64) -> i64 { bits / 8 }
fn hash_block(bits: i64) -> i64 { if bits == 256 { 64 } else { 128 } }

// One hash of a || b, by `bits`.
fn hash2(bits: i64, a: const u8[:], b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if bits == 256 {
        var s = sha256_init();
        sha256_update(s, a);
        sha256_update(s, b);
        out.append(sha256_final(s));
    } else {
        assert(bits == 384 || bits == 512);
        var s = if bits == 384 { sha384_init() } else { sha512_init() };
        sha512_update(s, a);
        sha512_update(s, b);
        out = sha512_final(s);
    }
    return out;
}

fn hash_bits(bits: i64, data: const u8[:]) -> u8[>..] { hash2(bits, data, "") }

// HMAC-SHA-`bits`(key, msg).
fn hmac(bits: i64, key: const u8[:], msg: const u8[:]) -> u8[>..] {
    let bl = hash_block(bits);
    var k: u8[128] = [0; 128];
    if key.len > bl {
        let hk = hash_bits(bits, key);
        for i in hk.len { k[i] = hk[i]; }
    } else {
        for i in key.len { k[i] = key[i]; }
    }
    var kpad: u8[128] = [0; 128];
    for i in bl { kpad[i] = k[i] ^ 0x36; }
    let inner = hash2(bits, kpad[..bl], msg);
    for i in bl { kpad[i] = k[i] ^ 0x5c; }
    return hash2(bits, kpad[..bl], inner);
}

fn hmac_sha256(key: const u8[:], msg: const u8[:]) -> u8[>..] { hmac(256, key, msg) }
fn hmac_sha384(key: const u8[:], msg: const u8[:]) -> u8[>..] { hmac(384, key, msg) }
fn hmac_sha512(key: const u8[:], msg: const u8[:]) -> u8[>..] { hmac(512, key, msg) }

// HKDF-Extract: PRK = HMAC(salt, ikm); an empty salt means hash-length zeros.
fn hkdf_extract(bits: i64, salt: const u8[:], ikm: const u8[:]) -> u8[>..] {
    if salt.len == 0 {
        var z: u8[64] = [0; 64];
        return hmac(bits, z[..hash_len(bits)], ikm);
    }
    return hmac(bits, salt, ikm);
}

// HKDF-Expand: `len` bytes (at most 255 hash lengths) from prk and info.
fn hkdf_expand(bits: i64, prk: const u8[:], info: const u8[:], len: i64) -> u8[>..] {
    let hl = hash_len(bits);
    assert(len >= 0 && len <= 255 * hl);
    var out: u8[>..] = [];
    var t: u8[>..] = [];
    var msg: u8[>..] = [];
    var counter = 1;
    while out.len < len {
        msg.clear();
        msg.append(t);
        msg.append(info);
        msg.push(counter as! u8);
        t = hmac(bits, prk, msg);
        let n = ::min(hl, len - out.len);
        out.append(t[..n]);
        counter++;
    }
    return out;
}

// Extract then expand.
fn hkdf(bits: i64, salt: const u8[:], ikm: const u8[:], info: const u8[:], len: i64) -> u8[>..] {
    let prk = hkdf_extract(bits, salt, ikm);
    return hkdf_expand(bits, prk, info, len);
}
