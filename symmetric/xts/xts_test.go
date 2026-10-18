package xts

import (
	"bytes"
	"crypto/aes"
	stdcipher "crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"testing"

	"github.com/moeghifar/mainecoon/errors"
	"github.com/moeghifar/mainecoon/internal/vectors"
)

// IEEE P1619/D16 Annex B, XTS-AES-256 vector 10 (512-byte data unit, sector 0xff).
func TestIEEE1619Vector10(t *testing.T) {
	key := vectors.MustHex("27182818284590452353602874713526624977572470936999595749669676273141592653589793238462643383279502884197169399375105820974944592")
	pt := vectors.MustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	want := vectors.MustHex("1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed43851ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151")
	got, err := Encrypt(key, pt, 0xff)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("encrypt: %v", err)
	}
	if back, err := Decrypt(key, got, 0xff); err != nil || !bytes.Equal(back, pt) {
		t.Fatal("decrypt")
	}
}

// NIST ACVP AES-XTS-256 vectors use arbitrary 128-bit tweaks, which x/crypto/xts cannot
// take. They are run through ref (SP 800-38E written out, test-only), and ref is then
// checked equal to the library on sector tweaks. Library == ref == ACVP.
func TestACVPViaReference(t *testing.T) {
	var f struct {
		TestGroups []struct {
			Direction string
			Tests     []struct {
				TcID        int `json:"tcId"`
				Key, Pt, Ct vectors.Hex
				TweakValue  vectors.Hex
			}
		}
	}
	vectors.Load(t, "testdata/acvp_xts.json", &f)
	n := 0
	for _, g := range f.TestGroups {
		for _, tc := range g.Tests {
			if len(tc.Key) != KeySize || len(tc.Pt)%block != 0 {
				continue
			}
			got := ref(tc.Key, tc.Pt, tc.TweakValue, true)
			if g.Direction != "encrypt" {
				got = ref(tc.Key, tc.Ct, tc.TweakValue, false)
			}
			want := tc.Ct
			if g.Direction != "encrypt" {
				want = tc.Pt
			}
			if !bytes.Equal(got, want) {
				t.Errorf("tc %d %s: reference disagrees with ACVP", tc.TcID, g.Direction)
			}
			n++
		}
	}
	if n == 0 {
		t.Fatal("no vectors")
	}
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i * 7)
	}
	data := bytes.Repeat([]byte("0123456789abcdef"), 32) // UT-SYM-010: 512 bytes
	for _, sector := range []uint64{0, 1, 255, 1 << 40} {
		got, _ := Encrypt(key, data, sector)
		if !bytes.Equal(got, ref(key, data, sectorTweak(sector), true)) {
			t.Fatalf("sector %d: library differs from reference", sector)
		}
	}
}

func TestRejects(t *testing.T) {
	key := make([]byte, KeySize)
	key[0] = 1
	if _, err := Encrypt(key, make([]byte, 17), 0); !errors.Is(err, errors.ErrInputBlockUnaligned) {
		t.Fatal("unaligned accepted")
	}
	if _, err := Encrypt(make([]byte, KeySize), make([]byte, 16), 0); !errors.Is(err, errors.ErrKeySizeInvalid) {
		t.Fatal("equal key halves accepted")
	}
	if _, err := Encrypt(key, make([]byte, MaxDataUnit+16), 0); !errors.Is(err, errors.ErrInputTooLarge) {
		t.Fatal("data unit above 2^20 blocks accepted")
	}
}

// ref is SP 800-38E / IEEE 1619 XTS without ciphertext stealing. Test-only.
func ref(key, src, tweak []byte, enc bool) []byte {
	k1, _ := aes.NewCipher(key[:32])
	k2, _ := aes.NewCipher(key[32:])
	dst := make([]byte, len(src))
	crypt(k1, k2, dst, src, tweak, enc)
	return dst
}

func crypt(k1, k2 stdcipher.Block, dst, src, tweak []byte, enc bool) {
	var t [block]byte
	k2.Encrypt(t[:], tweak)
	for i := 0; i < len(src); i += block {
		b := dst[i : i+block]
		subtle.XORBytes(b, src[i:i+block], t[:])
		if enc {
			k1.Encrypt(b, b)
		} else {
			k1.Decrypt(b, b)
		}
		subtle.XORBytes(b, b, t[:])
		carry := t[block-1] >> 7
		for j := block - 1; j > 0; j-- {
			t[j] = t[j]<<1 | t[j-1]>>7
		}
		t[0] = t[0]<<1 ^ 0x87*carry
	}
}

// sectorTweak is the IEEE 1619 tweak for sector n: 16-byte little-endian.
func sectorTweak(n uint64) []byte {
	t := make([]byte, block)
	binary.LittleEndian.PutUint64(t, n)
	return t
}
