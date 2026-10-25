// SHA-384, SHA-512, HMAC and HKDF against vectors/hash.txt (hashlib and
// hmac): lengths around SHA-512's 128-byte block and its padding boundary,
// each hash also fed in pieces; HMAC keys shorter and longer than a block;
// HKDF from RFC 5869's first test case and random ones.
import std;
import bigman from "..";
import bigman.hmac;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 10 { print("FAIL ", what); } }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn num(s: const u8[:]) -> i64 {
    let v, ok = parse_int(s, 10);
    assert(ok);
    return v;
}

fn main() {
    for line in split(embed_file("vectors/hash.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        if w[0] == "sha384" || w[0] == "sha512" {
            let m = unhex(w[1]);
            let want = unhex(w[2]);
            let is384 = w[0] == "sha384";
            check(line, (if is384 { bigman::sha384(m) } else { bigman::sha512(m) }) == want);
            var s = if is384 { bigman::sha384_init() } else { bigman::sha512_init() };
            var off = 0;
            var step = 1;
            while off < m.len {
                let end = ::min(m.len, off + step);
                bigman::sha512_update(s, m[off..end]);
                off = end;
                step += 3;
            }
            check(line, bigman::sha512_final(s) == want);
        } else if w[0] == "hmac" {
            check(line, bigman::hmac(num(w[1]), unhex(w[2]), unhex(w[3])) == unhex(w[4]));
        } else if w[0] == "hkdf" {
            let got = bigman::hkdf(num(w[1]), unhex(w[2]), unhex(w[3]), unhex(w[4]), num(w[5]));
            check(line, got == unhex(w[6]));
        }
    }
    check("hmac_sha256", bigman::hmac_sha256("key", "The quick brown fox jumps over the lazy dog")
          == unhex("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"));
    print("hash vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
