// bignum.entropy: cryptographically secure random bytes from the OS, by
// getentropy(3) (macOS, Linux, the BSDs). std's rng is splitmix64 and is
// not for keys.

namespace bignum;

import std;

extern fn getentropy(p: u8&, n: u64) -> i32;

// Fills out with random bytes; aborts if the OS cannot provide them.
fn random_bytes(out: u8[:]) {
    var off = 0;
    while off < out.len {
        let n = ::min(out.len - off, 256);       // getentropy's limit per call
        let rc = getentropy(out[off], n as u64);
        assert(rc == 0);
        off += n;
    }
}
