// examples/speed.goose's measurements with the RustCrypto crates: the same
// names, inputs and units ("name value unit", MB/s over 16 KiB buffers or
// operations a second), so scripts/speed_vs_rust.py can set them side by
// side. A name given as an argument runs only the lines it prefixes.
//
//   cargo run --release -- [--seconds S] [prefix]
use std::hint::black_box;
use std::time::Instant;

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{AsyncStreamCipher, BlockEncryptMut, InnerIvInit, KeyInit, KeyIvInit, StreamCipher, StreamCipherSeek};
use aes::{Aes128, Aes256};
use aes_gcm::aead::AeadInPlace;
use rand::rngs::OsRng;
use sha2::Digest;

const BUF: usize = 16384;

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
    fn mbps(&self, name: &str, f: impl FnMut()) {
        if self.wanted(name) {
            println!("{} {} MB/s", name, rate(self.secs, f) * BUF as f64 / 1e6);
        }
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

fn hash<D: Digest>(b: &Bench, name: &str, buf: &mut [u8]) {
    b.mbps(name, || {
        let h = D::digest(&*buf);
        buf[0] = h[0];
    });
}

fn hashes(b: &Bench, buf: &mut [u8]) {
    hash::<md5::Md5>(b, "md5", buf);
    hash::<sha1::Sha1>(b, "sha1", buf);
    hash::<sha2::Sha256>(b, "sha256", buf);
    hash::<sha2::Sha512>(b, "sha512", buf);
    hash::<sha3::Sha3_256>(b, "sha3-256", buf);
    hash::<blake2::Blake2b512>(b, "blake2b512", buf);
    hash::<blake2::Blake2s256>(b, "blake2s256", buf);
    let key = bytes_of(32, 1);
    b.mbps("hmac-sha256", || {
        use hmac::Mac;
        let mut m = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(&key).unwrap();
        m.update(buf);
        let h = m.finalize().into_bytes();
        buf[0] = h[0];
    });
}

fn ciphers(b: &Bench, buf: &mut [u8]) {
    let k16 = bytes_of(16, 2);
    let k32 = bytes_of(32, 3);
    let iv = bytes_of(16, 4);
    let nonce = bytes_of(12, 5);
    let g128 = aes_gcm::Aes128Gcm::new_from_slice(&k16).unwrap();
    b.mbps("aes-128-gcm", || {
        black_box(g128.encrypt_in_place_detached(nonce.as_slice().into(), b"", buf).unwrap());
    });
    let g256 = aes_gcm::Aes256Gcm::new_from_slice(&k32).unwrap();
    b.mbps("aes-256-gcm", || {
        black_box(g256.encrypt_in_place_detached(nonce.as_slice().into(), b"", buf).unwrap());
    });
    let cp = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&k32).unwrap();
    b.mbps("chacha20-poly1305", || {
        black_box(cp.encrypt_in_place_detached(nonce.as_slice().into(), b"", buf).unwrap());
    });
    b.mbps("chacha20", || {
        let mut c = chacha20::ChaCha20::new(k32.as_slice().into(), nonce.as_slice().into());
        c.seek(64u32); // block counter 1
        c.apply_keystream(buf);
    });
    // The key schedules are made once, as aes_init's are.
    let a128 = Aes128::new_from_slice(&k16).unwrap();
    let a256 = Aes256::new_from_slice(&k32).unwrap();
    b.mbps("aes-128-ctr", || {
        ctr::Ctr128BE::<Aes128>::from_core(ctr::CtrCore::inner_iv_slice_init(a128.clone(), &iv).unwrap()).apply_keystream(buf);
    });
    b.mbps("aes-256-ctr", || {
        ctr::Ctr128BE::<Aes256>::from_core(ctr::CtrCore::inner_iv_slice_init(a256.clone(), &iv).unwrap()).apply_keystream(buf);
    });
    b.mbps("aes-128-cbc", || {
        cbc::Encryptor::<Aes128>::inner_iv_slice_init(a128.clone(), &iv).unwrap().encrypt_padded_mut::<NoPadding>(buf, BUF).unwrap();
    });
    b.mbps("aes-256-cbc", || {
        cbc::Encryptor::<Aes256>::inner_iv_slice_init(a256.clone(), &iv).unwrap().encrypt_padded_mut::<NoPadding>(buf, BUF).unwrap();
    });
    b.mbps("aes-128-cfb", || {
        cfb_mode::Encryptor::<Aes128>::inner_iv_slice_init(a128.clone(), &iv).unwrap().encrypt(buf);
    });
    b.mbps("aes-128-ofb", || {
        ofb::Ofb::<Aes128>::from_core(ofb::OfbCore::inner_iv_slice_init(a128.clone(), &iv).unwrap()).apply_keystream(buf);
    });
    let d1 = des::Des::new_from_slice(&bytes_of(8, 6)).unwrap();
    let d3 = des::TdesEde3::new_from_slice(&bytes_of(24, 7)).unwrap();
    b.mbps("des-cbc", || {
        cbc::Encryptor::<des::Des>::inner_iv_slice_init(d1.clone(), &iv[..8]).unwrap().encrypt_padded_mut::<NoPadding>(buf, BUF).unwrap();
    });
    b.mbps("des-ede3-cbc", || {
        cbc::Encryptor::<des::TdesEde3>::inner_iv_slice_init(d3.clone(), &iv[..8]).unwrap().encrypt_padded_mut::<NoPadding>(buf, BUF).unwrap();
    });
    let mut r = rc4::Rc4::<rc4::consts::U16>::new(k16.as_slice().into());
    b.mbps("rc4", || r.apply_keystream(buf));
}

macro_rules! nist_curve {
    ($b:expr, $c:ident, $name:expr, $len:expr, $msg:expr) => {{
        let mut d = bytes_of($len, 11);
        d[0] = 1;
        let mut d2 = bytes_of($len, 12);
        d2[0] = 1;
        let sk = $c::SecretKey::from_slice(&d).unwrap();
                let peer = $c::SecretKey::from_slice(&d2).unwrap().public_key();
        $b.ops(&format!("ecdh-{}", $name), || {
            black_box($c::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine()));
        });
        use $c::ecdsa::signature::{Signer, Verifier};
        let signer = $c::ecdsa::SigningKey::from_slice(&d).unwrap();
        let verifier = $c::ecdsa::VerifyingKey::from(&signer);
        let sig: $c::ecdsa::Signature = signer.sign($msg);
        $b.ops(&format!("ecdsa-{}-sign", $name), || {
            let s: $c::ecdsa::Signature = signer.sign($msg);
            black_box(s);
        });
        $b.ops(&format!("ecdsa-{}-verify", $name), || {
            assert!(verifier.verify($msg, &sig).is_ok());
        });
    }};
}

fn curves(b: &Bench) {
    let msg = bytes_of(32, 8);
    let sk: [u8; 32] = bytes_of(32, 9).try_into().unwrap();
    let base = x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(bytes_of(32, 10)).unwrap());
    let pk = x25519_dalek::PublicKey::from(&base).to_bytes();
    b.ops("x25519", || {
        black_box(x25519_dalek::x25519(sk, pk));
    });
    {
        use ed25519_dalek::{Signer, Verifier};
        let key = ed25519_dalek::SigningKey::from_bytes(&sk);
        let vk = key.verifying_key();
        let sig = key.sign(&msg);
        b.ops("ed25519-sign", || {
            black_box(key.sign(&msg));
        });
        b.ops("ed25519-verify", || assert!(vk.verify(&msg, &sig).is_ok()));
    }
    nist_curve!(b, p224, "p224", 28, &msg);
    nist_curve!(b, p256, "p256", 32, &msg);
    nist_curve!(b, p384, "p384", 48, &msg);
    nist_curve!(b, p521, "p521", 66, &msg);
}

fn rsa_ops(b: &Bench) {
    use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
    let msg = bytes_of(32, 13);
    for bits in [2048usize, 3072, 4096] {
        let nm = format!("rsa{bits}");
        if !b.wanted(&nm) {
            continue;
        }
        let key = rsa::RsaPrivateKey::new(&mut OsRng, bits).unwrap();
        let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key.clone());
        let verifier = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key.to_public_key());
        let sig = signer.sign_with_rng(&mut OsRng, &msg);
        // With blinding, as RSA private-key operations should be.
        b.ops(&format!("{nm}-sign"), || {
            black_box(signer.sign_with_rng(&mut OsRng, &msg).to_bytes());
        });
        b.ops(&format!("{nm}-verify"), || assert!(verifier.verify(&msg, &sig).is_ok()));
    }
}

fn kem<K: ml_kem::KemCore>(b: &Bench, nm: &str, seed: &[u8]) {
    use ml_kem::kem::{Decapsulate, Encapsulate};
    if !b.wanted(nm) {
        return;
    }
    let d = ml_kem::B32::try_from(&seed[..32]).unwrap();
    let z = ml_kem::B32::try_from(&seed[32..]).unwrap();
    b.ops(&format!("{nm}-keygen"), || {
        black_box(K::generate_deterministic(&d, &z));
    });
    let (dk, ek) = K::generate_deterministic(&d, &z);
    b.ops(&format!("{nm}-encaps"), || {
        black_box(ek.encapsulate(&mut OsRng).unwrap());
    });
    let (c, _) = ek.encapsulate(&mut OsRng).unwrap();
    b.ops(&format!("{nm}-decaps"), || {
        black_box(dk.decapsulate(&c).unwrap());
    });
}

fn kems(b: &Bench) {
    kem::<ml_kem::MlKem512>(b, "mlkem512", &bytes_of(64, 16));
    kem::<ml_kem::MlKem768>(b, "mlkem768", &bytes_of(64, 17));
    kem::<ml_kem::MlKem1024>(b, "mlkem1024", &bytes_of(64, 18));
}

fn kdfs(b: &Bench) {
    let mut dk = [0u8; 32];
    b.ops("pbkdf2-sha256-100k", || {
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(b"password", b"saltsaltsaltsalt", 100000, &mut dk);
    });
    let sp = scrypt::Params::new(15, 8, 1, 32).unwrap();
    b.ops("scrypt-n15-r8", || {
        scrypt::scrypt(b"password", b"saltsaltsaltsalt", &sp, &mut dk).unwrap();
    });
    let ap = argon2::Params::new(65536, 1, 4, Some(32)).unwrap();
    let a2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, ap);
    b.ops("argon2id-t1-64m-p4", || {
        a2.hash_password_into(b"password", b"saltsaltsaltsalt", &mut dk).unwrap();
    });
    black_box(dk);
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
    let mut buf = bytes_of(BUF, 0);
    hashes(&b, &mut buf);
    ciphers(&b, &mut buf);
    curves(&b);
    rsa_ops(&b);
    kems(&b);
    kdfs(&b);
}
