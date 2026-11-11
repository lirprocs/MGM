package MGM

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"math/rand"
	"testing"
)

func mustPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: ожидалась паника", what)
		}
	}()
	f()
}

func bothCiphers(t *testing.T) map[string]cipher.Block {
	key := unhex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	return map[string]cipher.Block{"Кузнечик": newKuzn(t, key), "Магма": newMagma(t, key)}
}

// RFC 9058, п. 4.1: 0 < |A| + |P|. Без этой проверки имитовставка пустого
// сообщения равна E_K(0) при любом nonce, и её можно предъявить с чужим nonce.
func TestEmptyMessageAndDataRejected(t *testing.T) {
	for name, b := range bothCiphers(t) {
		aead, _ := New(b)
		nonce := make([]byte, aead.NonceSize())
		mustPanic(t, name+": Seal без данных и текста", func() { aead.Seal(nil, nonce, nil, nil) })

		// то, что прежняя версия выдавала как имитовставку пустого сообщения
		forged := make([]byte, b.BlockSize())
		b.Encrypt(forged, forged)
		nonce[len(nonce)-1] = 0x55
		if _, err := aead.Open(nil, nonce, forged, nil); err == nil {
			t.Fatalf("%s: Open принял E_K(0) как имитовставку пустого сообщения", name)
		}
		// по одному пустому — можно
		ct := aead.Seal(nil, nonce, nil, []byte("только данные"))
		if _, err := aead.Open(nil, nonce, ct, []byte("только данные")); err != nil {
			t.Fatalf("%s: пустой текст с данными: %v", name, err)
		}
		ct = aead.Seal(nil, nonce, []byte("только текст"), nil)
		if _, err := aead.Open(nil, nonce, ct, nil); err != nil {
			t.Fatalf("%s: текст без данных: %v", name, err)
		}
	}
}

// ICN занимает n − 1 бит. Если старший бит молча отбрасывать, два разных
// nonce дают одну гамму и одну имитовставку.
func TestNonceTopBitRejected(t *testing.T) {
	for name, b := range bothCiphers(t) {
		aead, _ := New(b)
		lo := make([]byte, aead.NonceSize())
		lo[0], lo[1] = 0x01, 0x02
		hi := append([]byte(nil), lo...)
		hi[0] |= 0x80
		p, a := []byte("сообщение"), []byte("данные")
		ct := aead.Seal(nil, lo, p, a)
		mustPanic(t, name+": Seal с единичным старшим битом nonce", func() { aead.Seal(nil, hi, p, a) })
		if _, err := aead.Open(nil, hi, ct, a); err == nil {
			t.Fatalf("%s: Open принял шифротекст с другим nonce", name)
		}
		if back, err := aead.Open(nil, lo, ct, a); err != nil || !bytes.Equal(back, p) {
			t.Fatalf("%s: свой nonce: %v", name, err)
		}
	}
}

// RFC 9058, п. 4.1: |A| + |P| < 2^(n/2) бит — ограничена сумма, а не каждая длина.
func TestTotalLengthLimit(t *testing.T) {
	if ^uint(0)>>32 == 0 {
		t.Skip("нужен 64-битный int")
	}
	magma := &mgm{n: 8, tagSize: 8}
	half := 1 << 28 // 2^28 байт = 2^31 бит
	if !magma.checkLengths(half, half-1) {
		t.Fatal("«Магма»: сумма 2^32 − 8 бит должна проходить")
	}
	if magma.checkLengths(half, half) {
		t.Fatal("«Магма»: сумма 2^32 бит должна отвергаться")
	}
	if magma.checkLengths(0, 0) {
		t.Fatal("нулевая сумма длин должна отвергаться")
	}
	kuzn := &mgm{n: 16, tagSize: 16}
	if !kuzn.checkLengths(1<<40, 1<<40) {
		t.Fatal("«Кузнечик»: 2 ТиБ должны проходить")
	}
}

// refMul — умножение бит за битом прямо по определению (прежняя реализация):
// эталон для табличного gfMulBlock.
func refMul(a, b []byte) gfElem {
	if len(a) == 16 {
		ah, al := binary.BigEndian.Uint64(a[:8]), binary.BigEndian.Uint64(a[8:])
		bh, bl := binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])
		var zh, zl uint64
		for i := 127; i >= 0; i-- {
			carry := zh >> 63
			zh = zh<<1 | zl>>63
			zl = zl<<1 ^ (0x87 & -carry)
			var bit uint64
			if i >= 64 {
				bit = bh >> uint(i-64) & 1
			} else {
				bit = bl >> uint(i) & 1
			}
			zh ^= ah & -bit
			zl ^= al & -bit
		}
		return gfElem{zh, zl}
	}
	av, bv := binary.BigEndian.Uint64(a), binary.BigEndian.Uint64(b)
	var z uint64
	for i := 63; i >= 0; i-- {
		carry := z >> 63
		z = z<<1 ^ (0x1b & -carry)
		z ^= av & -(bv >> uint(i) & 1)
	}
	return gfElem{0, z}
}

func TestGFMulMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for _, n := range []int{8, 16} {
		a, b := make([]byte, n), make([]byte, n)
		edge := [][]byte{make([]byte, n), bytes.Repeat([]byte{0xff}, n), append(make([]byte, n-1), 1), append([]byte{0x80}, make([]byte, n-1)...)}
		for _, x := range edge {
			for _, y := range edge {
				if gfMulBlock(x, y) != refMul(x, y) {
					t.Fatalf("n=%d: %x * %x", n, x, y)
				}
			}
		}
		for i := 0; i < 100000; i++ {
			rng.Read(a)
			rng.Read(b)
			if gfMulBlock(a, b) != refMul(a, b) {
				t.Fatalf("n=%d: %x * %x", n, a, b)
			}
		}
	}
}

// Шифрование и расшифрование на месте (dst = src[:0]), как разрешает cipher.AEAD.
func TestInPlace(t *testing.T) {
	for name, b := range bothCiphers(t) {
		aead, _ := New(b)
		nonce := make([]byte, aead.NonceSize())
		p := []byte("шифрование на месте, длина не кратна блоку")
		want := aead.Seal(nil, nonce, p, []byte("a"))
		buf := make([]byte, len(p), len(p)+aead.Overhead())
		copy(buf, p)
		got := aead.Seal(buf[:0], nonce, buf, []byte("a"))
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: Seal на месте расходится", name)
		}
		back, err := aead.Open(got[:0], nonce, got, []byte("a"))
		if err != nil || !bytes.Equal(back, p) {
			t.Fatalf("%s: Open на месте: %v", name, err)
		}
	}
}

// Прежний Decrypt не должен паниковать на пустом шифротексте.
func TestLegacyDecryptEmpty(t *testing.T) {
	var key [32]byte
	var nonce [16]byte
	if err, _, _ := Decrypt(nil, make([]byte, 16), nil, key, nonce); err == nil {
		t.Fatal("ожидалась ошибка")
	}
}

func FuzzSealOpen(f *testing.F) {
	f.Add([]byte("текст"), []byte("данные"), []byte{1, 2, 3, 4, 5, 6, 7, 8})
	f.Add([]byte{}, []byte{0}, []byte{})
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	b, err := newMagmaCipher(key)
	if err != nil {
		f.Fatal(err)
	}
	aead, _ := New(b)
	f.Fuzz(func(t *testing.T, p, a, n []byte) {
		if len(p)+len(a) == 0 {
			return
		}
		nonce := make([]byte, 8)
		copy(nonce, n)
		nonce[0] &= 0x7f
		ct := aead.Seal(nil, nonce, p, a)
		back, err := aead.Open(nil, nonce, ct, a)
		if err != nil || !bytes.Equal(back, p) {
			t.Fatalf("не расшифровалось: %v", err)
		}
		ct[len(ct)-1] ^= 1
		if _, err := aead.Open(nil, nonce, ct, a); err == nil {
			t.Fatal("искажение не обнаружено")
		}
	})
}

func benchSeal(b *testing.B, blk cipher.Block, size int) {
	aead, _ := New(blk)
	nonce := make([]byte, aead.NonceSize())
	p := make([]byte, size)
	dst := make([]byte, 0, size+aead.Overhead())
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aead.Seal(dst, nonce, p, nil)
	}
}

func BenchmarkSealMagma1K(b *testing.B) {
	c, _ := newMagmaCipher(make([]byte, 32))
	benchSeal(b, c, 1024)
}

func BenchmarkGFMul128(b *testing.B) {
	x, y := bytes.Repeat([]byte{0x5a}, 16), bytes.Repeat([]byte{0xc3}, 16)
	var acc gfElem
	for i := 0; i < b.N; i++ {
		acc.xor(gfMulBlock(x, y))
	}
}

func BenchmarkGFMul64(b *testing.B) {
	x, y := bytes.Repeat([]byte{0x5a}, 8), bytes.Repeat([]byte{0xc3}, 8)
	var acc gfElem
	for i := 0; i < b.N; i++ {
		acc.xor(gfMulBlock(x, y))
	}
}
