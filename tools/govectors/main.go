// Vectors from Go's golang.org/x/crypto for the packages bignum matches:
// MD4, RIPEMD-160, Salsa20 and XSalsa20, HSalsa20, NaCl secretbox, box
// (and its anonymous form), sign and auth, bcrypt, Blowfish, CAST5,
// Twofish, TEA, XTEA, AES-XTS and bcrypt_pbkdf (x/crypto/ssh's internal
// package, copied to internal/bcrypt_pbkdf). One line a case on stdout; the random
// stream is fixed, so the output is too (bcrypt aside, whose salts come
// from crypto/rand; its lines are checked by recomputing from the salt).
//
//	tools/govectors.sh > test/vectors/xcrypto.txt
//	tools/govectors.sh --check   # compares with it instead
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/nacl/auth"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/nacl/sign"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/salsa20/salsa"
	"golang.org/x/crypto/tea"
	"golang.org/x/crypto/twofish"
	"golang.org/x/crypto/xtea"
	"golang.org/x/crypto/xts"

	"govectors/internal/bcrypt_pbkdf"
)

var rng = rand.New(rand.NewChaCha8([32]byte{'g', 'o', 'o', 's', 'e'}))

func rb(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
	return b
}

func line(fields ...any) {
	parts := make([]string, len(fields))
	for i, f := range fields {
		switch v := f.(type) {
		case []byte:
			if len(v) == 0 {
				parts[i] = "-"
			} else {
				parts[i] = hex.EncodeToString(v)
			}
		default:
			parts[i] = fmt.Sprint(v)
		}
	}
	fmt.Println(strings.Join(parts, " "))
}

// Lengths around the 64-byte block boundaries.
var lengths = []int{0, 1, 3, 31, 32, 33, 55, 56, 57, 63, 64, 65, 100, 127, 128, 129, 1000}

// A reader that hands out the given bytes, for the keys of GenerateKey
// and SealAnonymous.
type fixed struct{ b []byte }

func (f *fixed) Read(p []byte) (int, error) {
	n := copy(p, f.b)
	f.b = f.b[n:]
	return n, nil
}

// Four blocks through the cipher both ways, and three blocks of CBC.
func blocks(name string, c cipher.Block, key []byte, extra ...any) {
	head := append([]any{name, key}, extra...)
	for i := 0; i < 4; i++ {
		pt := rb(c.BlockSize())
		ct := make([]byte, len(pt))
		c.Encrypt(ct, pt)
		back := make([]byte, len(pt))
		c.Decrypt(back, ct)
		if !bytes.Equal(back, pt) {
			panic(name)
		}
		line(append(append([]any{}, head...), pt, ct)...)
	}
	iv := rb(c.BlockSize())
	pt := rb(3 * c.BlockSize())
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(c, iv).CryptBlocks(ct, pt)
	cbc := append([]any{name + "-cbc", key}, extra...)
	line(append(cbc, iv, pt, ct)...)
}

func main() {
	for _, n := range lengths {
		m := rb(n)
		d4 := md4.New()
		d4.Write(m)
		line("md4", m, d4.Sum(nil))
		d := ripemd160.New()
		d.Write(m)
		line("ripemd160", m, d.Sum(nil))
	}
	for _, nl := range []int{8, 24} {
		for _, n := range []int{0, 1, 63, 64, 65, 200} {
			var key [32]byte
			copy(key[:], rb(32))
			nonce := rb(nl)
			m := rb(n)
			out := make([]byte, n)
			salsa20.XORKeyStream(out, m, nonce, &key)
			line("salsa20", key[:], nonce, m, out)
		}
	}
	for i := 0; i < 3; i++ {
		var key [32]byte
		var in [16]byte
		var out [32]byte
		copy(key[:], rb(32))
		copy(in[:], rb(16))
		salsa.HSalsa20(&out, &in, &key, &salsa.Sigma)
		line("hsalsa20", key[:], in[:], out[:])
	}
	for _, n := range []int{0, 1, 31, 32, 33, 64, 100} {
		var key [32]byte
		var nonce [24]byte
		copy(key[:], rb(32))
		copy(nonce[:], rb(24))
		m := rb(n)
		line("secretbox", key[:], nonce[:], m, secretbox.Seal(nil, m, &nonce, &key))
	}
	for _, n := range []int{0, 5, 40, 100} {
		pa, sa, _ := box.GenerateKey(&fixed{rb(32)})
		pb, sb, _ := box.GenerateKey(&fixed{rb(32)})
		var nonce [24]byte
		copy(nonce[:], rb(24))
		m := rb(n)
		line("box", sa[:], pa[:], sb[:], pb[:], nonce[:], m, box.Seal(nil, m, &nonce, pb, sa))
		esk := rb(32)
		anon, err := box.SealAnonymous(nil, m, pb, &fixed{append([]byte{}, esk...)})
		if err != nil {
			panic(err)
		}
		line("anon", sb[:], pb[:], esk, m, anon)
	}
	for _, n := range []int{0, 1, 64, 100} {
		priv := ed25519.NewKeyFromSeed(rb(32))
		var sk [64]byte
		copy(sk[:], priv)
		m := rb(n)
		line("sign", sk[:], []byte(priv.Public().(ed25519.PublicKey)), m, sign.Sign(nil, m, &sk))
	}
	for _, n := range []int{0, 1, 100} {
		var key [32]byte
		copy(key[:], rb(32))
		m := rb(n)
		line("auth", key[:], m, auth.Sum(m, &key)[:])
	}
	for i, pw := range [][]byte{{}, []byte("U*U"), []byte("password"), rb(40), rb(72)} {
		cost := 4 + i%3
		hash, err := bcrypt.GenerateFromPassword(pw, cost)
		if err != nil {
			panic(err)
		}
		line("bcrypt", pw, cost, string(hash))
	}
	for _, kl := range []int{4, 16, 56} {
		key := rb(kl)
		c, _ := blowfish.NewCipher(key)
		blocks("blowfish", c, key)
	}
	key := rb(16)
	c5, _ := cast5.NewCipher(key)
	blocks("cast5", c5, key)
	for _, kl := range []int{16, 24, 32} {
		key := rb(kl)
		c, _ := twofish.NewCipher(key)
		blocks("twofish", c, key)
	}
	for _, rounds := range []int{64, 32} {
		key := rb(16)
		c, _ := tea.NewCipherWithRounds(key, rounds)
		blocks("tea", c, key, rounds)
	}
	key = rb(16)
	cx, _ := xtea.NewCipher(key)
	blocks("xtea", cx, key)
	for _, kl := range []int{32, 64} {
		key := rb(kl)
		c, _ := xts.NewCipher(aes.NewCipher, key)
		for _, n := range []int{16, 32, 64, 512} {
			sector := rng.Uint64() >> uint(rng.IntN(64))
			pt := rb(n)
			ct := make([]byte, n)
			c.Encrypt(ct, pt, sector)
			line("xts", key, sector, pt, ct)
		}
	}

	// bcrypt_pbkdf: OpenBSD's three vectors (Go's tests), then lengths
	// around its 32-byte blocks and the 48 bytes of aes256-ctr's key and IV.
	type pbkdf struct {
		pw, salt []byte
		rounds, n int
	}
	cases := []pbkdf{
		{[]byte("password"), []byte("salt"), 12, 32},
		{[]byte("passwordy\x00PASSWORD\x00"), []byte("salty\x00SALT\x00"), 3, 32},
		{[]byte("секретное слово"), []byte("посолить немножко"), 8, 88},
	}
	for i, n := range []int{1, 16, 31, 32, 33, 48, 64, 65, 100} {
		cases = append(cases, pbkdf{rb(1 + rng.IntN(40)), rb(16), 1 + i%3, n})
	}
	cases = append(cases, pbkdf{rb(72), rb(1), 16, 48})
	for _, p := range cases {
		k, err := bcrypt_pbkdf.Key(p.pw, p.salt, p.rounds, p.n)
		if err != nil {
			panic(err)
		}
		line("bcrypt_pbkdf", p.pw, p.salt, p.rounds, k)
	}
}
