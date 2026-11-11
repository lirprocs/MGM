package MGM

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"

	"github.com/lirprocs/Kuznyechik/KuznEncrypt"
)

// kuznBlock — cipher.Block поверх KuznEncrypt (только зашифрование, его хватает MGM).
type kuznBlock struct{ key [32]byte }

func (k kuznBlock) BlockSize() int { return 16 }
func (k kuznBlock) Encrypt(dst, src []byte) {
	var in [16]byte
	copy(in[:], src)
	out := KuznEncrypt.Encrypt(in, k.key)
	copy(dst, out[:])
}
func (k kuznBlock) Decrypt(dst, src []byte) { panic("не нужно для MGM") }

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "\n", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newKuzn(t *testing.T, key []byte) cipher.Block {
	var k [32]byte
	copy(k[:], key)
	return kuznBlock{k}
}

func newMagma(t *testing.T, key []byte) cipher.Block {
	b, err := newMagmaCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Примеры из RFC 9058, приложение A.
var rfcVectors = []struct {
	name                   string
	magma                  bool
	key, nonce, a, p, c, t string
}{
	{
		name:  "Кузнечик, пример 1 (A.1.1)",
		key:   "8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF",
		nonce: "112233445566770 0FFEEDDCCBBAA9988",
		a:     "0202020202020202010101010101010104040404040404040303030303030303EA0505050505050505",
		p: "1122334455667700FFEEDDCCBBAA998800112233445566778899AABBCCEEFF0A" +
			"112233445566778899AABBCCEEFF0A002233445566778899AABBCCEEFF0A0011AABBCC",
		c: "A9757B8147956E9055B8A33DE89F42FC8075D2212BF9FD5BD3F7069AADC16B39" +
			"497AB15915A6BA85936B5D0EA9F6851CC60C14D4D3F883D0AB94420695C76DEB2C7552",
		t: "CF5D656F40C34F5C46E8BB0E29FCDB4C",
	},
	{
		name:  "Кузнечик, пример 2 (A.1.2)",
		key:   "99AABBCCDDEEFF00112233445566 77FEDCBA98765432100123456789ABCDEF88",
		nonce: "1122334455667700FFEEDDCCBBAA9988",
		a:     "01010101010101010101010101010101",
		t:     "7901E9EA2085CD247ED249695F9F8A85",
	},
	{
		name:  "Магма, пример 1 (A.2.1)",
		magma: true,
		key:   "FFEEDDCCBBAA99887766554433221100F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
		nonce: "12DEF06B3C130A59",
		a:     "01010101010101010202020202020202030303030303030304040404040404040505050505050505EA",
		p: "FFEEDDCCBBAA998811223344556677008899AABBCCEEFF0A0011223344556677" +
			"99AABBCCEEFF0A001122334455667788AABBCCEEFF0A0011223344556677 8899AABBCC",
		c: "C795066C5F9EA03B8511334245918 5AE1F2E00D6BF2B785D940470B8BB9C8E7D" +
			"9A5DD3731F7DDC70EC27CB0ACE6FA57670F65C646ABB75D547AA37C3BCB5C34E03BB9C",
		t: "A7928069AA10FD10",
	},
	{
		name:  "Магма, пример 2 (A.2.2)",
		magma: true,
		key:   "99AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF88",
		nonce: "0077665544332211",
		p:     "2233445566 7700FF",
		c:     "6A95E1426B259D4E",
		t:     "334EE270450BEC9E",
	},
}

func TestNewRFC9058(t *testing.T) {
	for _, v := range rfcVectors {
		t.Run(v.name, func(t *testing.T) {
			key := unhex(t, v.key)
			var b cipher.Block
			if v.magma {
				b = newMagma(t, key)
			} else {
				b = newKuzn(t, key)
			}
			aead, err := New(b)
			if err != nil {
				t.Fatal(err)
			}
			nonce, a, p := unhex(t, v.nonce), unhex(t, v.a), unhex(t, v.p)
			want := append(unhex(t, v.c), unhex(t, v.t)...)
			got := aead.Seal(nil, nonce, p, a)
			if !bytes.Equal(got, want) {
				t.Fatalf("Seal:\n got %X\nwant %X", got, want)
			}
			back, err := aead.Open(nil, nonce, got, a)
			if err != nil || !bytes.Equal(back, p) {
				t.Fatalf("Open: err=%v, got %X, want %X", err, back, p)
			}
		})
	}
}

func TestMagmaBlockRFC8891(t *testing.T) {
	b := newMagma(t, unhex(t, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
	out := make([]byte, 8)
	b.Encrypt(out, unhex(t, "fedcba9876543210"))
	if hex.EncodeToString(out) != "4ee901e5c2d8ca3d" {
		t.Fatalf("Магма: %x", out)
	}
	b.Decrypt(out, out)
	if hex.EncodeToString(out) != "fedcba9876543210" {
		t.Fatalf("Магма, расшифрование: %x", out)
	}
}

// Новый интерфейс и исходный Encrypt должны давать одно и то же, в том числе
// на сообщениях длиннее 256 блоков (проверка исправления счётчиков).
func TestNewMatchesLegacy(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var key [32]byte
	rng.Read(key[:])
	aead, _ := New(newKuzn(t, key[:]))
	for _, l := range []int{0, 1, 15, 16, 17, 100, 4096, 300*16 + 5} {
		p := make([]byte, l)
		a := make([]byte, l%37)
		rng.Read(p)
		rng.Read(a)
		var nonce [16]byte
		rng.Read(nonce[:])
		nonce[0] &= 0x7f // ICN — n − 1 бит
		nonce[15] = 0xF0 // правая половина Y_1 близка к переполнению байта
		nonce[7] = 0xF0
		if len(a) == 0 && l == 0 {
			a = []byte{1} // пустые данные и текст одновременно запрещены
		}
		_, cBlocks, tag := Encrypt(a, p, key, nonce)
		var legacy []byte
		for _, b := range cBlocks {
			legacy = append(legacy, b[:]...)
		}
		legacy = append(legacy[:l], tag...)
		got := aead.Seal(nil, nonce[:], p, a)
		if !bytes.Equal(got, legacy) {
			t.Fatalf("длина %d: New и Encrypt расходятся", l)
		}
	}
}

func TestNoKeystreamReuse(t *testing.T) {
	var key [32]byte
	aead, _ := New(newKuzn(t, key[:]))
	nonce := make([]byte, 16)
	ct := aead.Seal(nil, nonce, make([]byte, 300*16), nil)
	for i := 0; i+256 < 300; i++ {
		if bytes.Equal(ct[i*16:i*16+16], ct[(i+256)*16:(i+256)*16+16]) {
			t.Fatalf("гамма блока %d повторилась в блоке %d", i, i+256)
		}
	}
}

func TestIncr(t *testing.T) {
	y := [16]byte{8: 0x00, 9: 0x00, 14: 0xff, 15: 0xff}
	y = incrR(y)
	if y[13] != 1 || y[14] != 0 || y[15] != 0 {
		t.Fatalf("incrR без переноса: %X", y)
	}
	full := [16]byte{0xaa, 8: 0xff, 9: 0xff, 10: 0xff, 11: 0xff, 12: 0xff, 13: 0xff, 14: 0xff, 15: 0xff}
	full = incrR(full)
	if full[0] != 0xaa || full[7] != 0 || full[8] != 0 || full[15] != 0 {
		t.Fatalf("incrR должен переполняться только внутри правой половины: %X", full)
	}
	z := [16]byte{6: 0x01, 7: 0xff, 8: 0x55}
	z = incrL(z)
	if z[6] != 2 || z[7] != 0 || z[8] != 0x55 {
		t.Fatalf("incrL: %X", z)
	}
}

func TestRoundTripAndTamper(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for _, magma := range []bool{false, true} {
		key := make([]byte, 32)
		rng.Read(key)
		var b cipher.Block
		if magma {
			b = newMagma(t, key)
		} else {
			b = newKuzn(t, key)
		}
		aead, _ := New(b)
		for _, l := range []int{0, 1, 7, 8, 9, 31, 64, 1000} {
			nonce := make([]byte, aead.NonceSize())
			rng.Read(nonce)
			nonce[0] &= 0x7f // ICN — n − 1 бит
			p := make([]byte, l)
			rng.Read(p)
			if l > 0 {
				p[l-1] = 0 // нули в конце текста должны сохраняться
			}
			a := []byte("доп. данные")
			ct := aead.Seal(nil, nonce, p, a)
			if len(ct) != l+aead.Overhead() {
				t.Fatalf("длина шифротекста %d", len(ct))
			}
			back, err := aead.Open(nil, nonce, ct, a)
			if err != nil || !bytes.Equal(back, p) {
				t.Fatalf("magma=%v l=%d: не расшифровалось", magma, l)
			}
			ct[rng.Intn(len(ct))] ^= 1 << uint(rng.Intn(8))
			if _, err := aead.Open(nil, nonce, ct, a); err == nil {
				t.Fatalf("magma=%v l=%d: искажение не обнаружено", magma, l)
			}
		}
	}
}

// Шифротекст, оканчивающийся нулевым байтом, должен расшифровываться
// (исходный Decrypt такие сообщения отвергает).
func TestCiphertextEndingWithZero(t *testing.T) {
	var key [32]byte
	aead, _ := New(newKuzn(t, key[:]))
	nonce := make([]byte, 16)
	for i := 0; i < 2000; i++ {
		nonce[15], nonce[14] = byte(i), byte(i>>8)
		p := []byte("сообщение")
		ct := aead.Seal(nil, nonce, p, nil)
		if ct[len(p)-1] != 0 {
			continue
		}
		if back, err := aead.Open(nil, nonce, ct, nil); err != nil || !bytes.Equal(back, p) {
			t.Fatalf("nonce %d: шифротекст с 00 в конце не расшифровался", i)
		}
		return
	}
	t.Skip("не встретилось шифротекста с нулём в конце")
}

func TestShortTag(t *testing.T) {
	var key [32]byte
	if _, err := NewWithTagSize(newKuzn(t, key[:]), 3); err == nil {
		t.Fatal("имитовставка 3 байта должна отвергаться")
	}
	aead, err := NewWithTagSize(newKuzn(t, key[:]), 8)
	if err != nil {
		t.Fatal(err)
	}
	full, _ := New(newKuzn(t, key[:]))
	nonce := make([]byte, 16)
	a := aead.Seal(nil, nonce, []byte("x"), nil)
	b := full.Seal(nil, nonce, []byte("x"), nil)
	if !bytes.Equal(a, b[:len(a)]) {
		t.Fatal("укороченная имитовставка — не префикс полной")
	}
}
