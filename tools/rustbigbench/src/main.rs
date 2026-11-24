// examples/bigint_speed.goose's measurements in Rust: num-bigint for the
// general integers, crypto-bigint for the constant-time Montgomery
// exponentiation. The same names, the same inputs and the same output
// ("name value op/s"), so scripts/bigint_vs_rust.py can set them side by
// side. A name given as an argument runs only the lines it prefixes.
//
//   cargo run --release -- [--seconds S] [prefix]
use std::hint::black_box;
use std::time::Instant;

use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{U2048, U4096};
use num_bigint::BigUint;
use num_integer::Integer;

struct Bench {
    only: String,
    secs: f64,
}

// Runs f until secs have passed and returns calls per second.
fn rate(secs: f64, mut f: impl FnMut()) -> f64 {
    let t0 = Instant::now();
    let mut n = 0u64;
    loop {
        f();
        n += 1;
        let s = t0.elapsed().as_secs_f64();
        if s >= secs {
            return n as f64 / s;
        }
    }
}

impl Bench {
    fn wanted(&self, name: &str) -> bool {
        name.starts_with(&self.only)
    }
    fn ops(&self, name: &str, f: impl FnMut()) {
        if self.wanted(name) {
            println!("{} {} op/s", name, rate(self.secs, f));
        }
    }
}

fn bytes_of(n: usize, seed: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 131 + seed * 17 + 7) % 251) as u8).collect()
}

// As in bigint_speed.goose: exactly `bits` bits, odd when asked.
fn number_bytes(bits: usize, seed: usize, odd: bool) -> Vec<u8> {
    let mut b = bytes_of(bits / 8, seed);
    b[0] |= 128;
    if odd {
        let l = b.len() - 1;
        b[l] |= 1;
    }
    b
}

fn number(bits: usize, seed: usize, odd: bool) -> BigUint {
    BigUint::from_bytes_be(&number_bytes(bits, seed, odd))
}

fn below_bytes(bits: usize, seed: usize) -> Vec<u8> {
    let mut b = bytes_of(bits / 8, seed);
    b[0] = (b[0] & 127) | 64;
    b
}

fn below(bits: usize, seed: usize) -> BigUint {
    BigUint::from_bytes_be(&below_bytes(bits, seed))
}

fn arith(b: &Bench) {
    for bits in [256usize, 1024, 4096, 16384, 65536] {
        let x = number(bits, 1, false);
        let y = below(bits, 2);
        b.ops(&format!("add-{bits}"), || {
            black_box(&x + &y);
        });
        b.ops(&format!("sub-{bits}"), || {
            black_box(&x - &y);
        });
        b.ops(&format!("mul-{bits}"), || {
            black_box(&x * &y);
        });
        b.ops(&format!("sqr-{bits}"), || {
            black_box(&x * &x);
        });
        b.ops(&format!("shl-{bits}"), || {
            black_box(&x << 13u32);
        });
        b.ops(&format!("shr-{bits}"), || {
            black_box(&x >> 13u32);
        });
        if bits <= 16384 {
            let n = number(bits, 3, false) * number(bits, 4, false);
            b.ops(&format!("divmod-{bits}"), || {
                black_box(n.div_rem(&x));
            });
        }
    }
}

macro_rules! ct_modexp {
    ($b:expr, $u:ty, $bits:expr) => {{
        let m = <$u>::from_be_slice(&number_bytes($bits, 5, true));
        let x = <$u>::from_be_slice(&below_bytes($bits, 6));
        let e = <$u>::from_be_slice(&number_bytes($bits, 7, false));
        let params = DynResidueParams::new(&m);
        let xr = DynResidue::new(&x, params);
        $b.ops(&format!("mont-modexp-{}", $bits), || {
            black_box(xr.pow(&e).retrieve());
        });
    }};
}

fn number_theory(b: &Bench) {
    for bits in [1024usize, 2048, 4096] {
        let m = number(bits, 5, true);
        let x = below(bits, 6);
        let e = number(bits, 7, false);
        b.ops(&format!("modpow-{bits}"), || {
            black_box(x.modpow(&e, &m));
        });
        if bits == 2048 {
            ct_modexp!(b, U2048, 2048);
        }
        if bits == 4096 {
            ct_modexp!(b, U4096, 4096);
        }
        if bits != 2048 {
            let y = number(bits, 8, false);
            b.ops(&format!("gcd-{bits}"), || {
                black_box(e.gcd(&y));
            });
            b.ops(&format!("modinv-{bits}"), || {
                black_box(x.modinv(&m).unwrap());
            });
        }
    }
}

fn text(b: &Bench) {
    for bits in [4096usize, 65536] {
        let a = number(bits, 9, false);
        let s = a.to_string();
        b.ops(&format!("to_str-{bits}"), || {
            black_box(a.to_string());
        });
        b.ops(&format!("parse-{bits}"), || {
            black_box(s.parse::<BigUint>().unwrap());
        });
    }
}

fn main() {
    let mut b = Bench { only: String::new(), secs: 0.5 };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--seconds" {
            b.secs = args.next().and_then(|s| s.parse().ok()).expect("--seconds S");
        } else {
            b.only = a;
        }
    }
    arith(&b);
    number_theory(&b);
    text(&b);
}
