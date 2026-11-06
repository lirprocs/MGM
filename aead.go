package MGM

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// Режим MGM (Multilinear Galois Mode) по Р 1323565.1.026-2019 и RFC 9058
// для любого блочного шифра с длиной блока 64 бита («Магма») или 128 бит
// («Кузнечик»). Реализует стандартный интерфейс cipher.AEAD:
//
//	block, _ := kuznyechik.New(key)   // любой cipher.Block с блоком 8 или 16 байт
//	aead, _ := MGM.New(block)
//	ct := aead.Seal(nil, nonce, plaintext, additionalData) // шифротекст || имитовставка
//	pt, err := aead.Open(nil, nonce, ct, additionalData)
//
// Nonce (ICN) — блок длиной n бит; по стандарту ICN занимает n−1 бит,
// поэтому старший бит первого байта nonce не используется (как и в Encrypt).

const (
	minTagSize = 4 // RFC 9058: длина имитовставки S от 32 до n бит
)

type mgm struct {
	b       cipher.Block
	n       int // длина блока в байтах: 8 или 16
	tagSize int
}

// New возвращает MGM с имитовставкой во весь блок (8 или 16 байт).
func New(b cipher.Block) (cipher.AEAD, error) {
	return NewWithTagSize(b, b.BlockSize())
}

// NewWithTagSize возвращает MGM с укороченной имитовставкой (от 4 байт до длины блока).
func NewWithTagSize(b cipher.Block, tagSize int) (cipher.AEAD, error) {
	n := b.BlockSize()
	if n != 8 && n != 16 {
		return nil, fmt.Errorf("MGM: длина блока %d байт, поддерживаются 8 и 16", n)
	}
	if tagSize < minTagSize || tagSize > n {
		return nil, fmt.Errorf("MGM: длина имитовставки %d байт, допустимо от %d до %d", tagSize, minTagSize, n)
	}
	return &mgm{b: b, n: n, tagSize: tagSize}, nil
}

func (m *mgm) NonceSize() int { return m.n }
func (m *mgm) Overhead() int  { return m.tagSize }

var errOpen = errors.New("MGM: имитовставка не совпала — данные или дополнительные данные изменены, либо ключ неверный")

// maxBlocks — сколько блоков можно обработать под одним nonce: счётчики
// Y и Z занимают по половине блока и не должны переполниться (RFC 9058, п. 4).
func (m *mgm) maxBlocks() uint64 {
	if m.n == 16 {
		return ^uint64(0) // 2^64 − 1: на практике недостижимо
	}
	return uint64(1) << 32
}

func (m *mgm) checkLengths(lenA, lenC int) bool {
	n := uint64(m.n)
	blocks := (uint64(lenA)+n-1)/n + (uint64(lenC)+n-1)/n + 1
	// длины в битах записываются в половину блока
	bitLimit := uint64(1)<<uint(4*m.n) - 1
	if m.n == 16 {
		bitLimit = ^uint64(0)
	}
	return blocks <= m.maxBlocks() &&
		uint64(lenA) <= bitLimit/8 && uint64(lenC) <= bitLimit/8
}

func (m *mgm) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != m.n {
		panic("MGM: неверная длина nonce")
	}
	if !m.checkLengths(len(additionalData), len(plaintext)) {
		panic("MGM: слишком длинное сообщение для одного nonce")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+m.tagSize)
	ct := out[:len(plaintext)]
	m.crypt(ct, plaintext, nonce)
	m.tag(out[len(plaintext):], nonce, additionalData, ct)
	return ret
}

func (m *mgm) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != m.n {
		panic("MGM: неверная длина nonce")
	}
	if len(ciphertext) < m.tagSize {
		return nil, errOpen
	}
	ct := ciphertext[:len(ciphertext)-m.tagSize]
	gotTag := ciphertext[len(ciphertext)-m.tagSize:]
	if !m.checkLengths(len(additionalData), len(ct)) {
		return nil, errOpen
	}
	want := make([]byte, m.tagSize)
	m.tag(want, nonce, additionalData, ct)
	if subtle.ConstantTimeCompare(want, gotTag) != 1 {
		return nil, errOpen
	}
	ret, out := sliceForAppend(dst, len(ct))
	m.crypt(out, ct, nonce)
	return ret, nil
}

// crypt — гаммирование: C_i = P_i ⊕ E_K(Y_i), Y_1 = E_K(0||ICN), Y_{i+1} = incr_r(Y_i).
func (m *mgm) crypt(dst, src, nonce []byte) {
	n := m.n
	y := make([]byte, n)
	copy(y, nonce)
	y[0] &= 0x7f
	m.b.Encrypt(y, y)
	ks := make([]byte, n)
	for off := 0; off < len(src); off += n {
		m.b.Encrypt(ks, y)
		end := off + n
		if end > len(src) {
			end = len(src)
		}
		subtle.XORBytes(dst[off:end], src[off:end], ks[:end-off])
		incrHalf(y[n/2:])
	}
}

// tag — имитовставка: T = MSB_S(E_K(Σ H_i ⊗ A_i ⊕ Σ H_{h+j} ⊗ C_j ⊕ H_{h+q+1} ⊗ (len(A)||len(C)))),
// Z_1 = E_K(1||ICN), H_i = E_K(Z_i), Z_{i+1} = incr_l(Z_i).
func (m *mgm) tag(out, nonce, a, c []byte) {
	n := m.n
	z := make([]byte, n)
	copy(z, nonce)
	z[0] |= 0x80
	m.b.Encrypt(z, z)

	h := make([]byte, n)
	blk := make([]byte, n)
	var acc gfElem
	absorb := func(data []byte) {
		for off := 0; off < len(data); off += n {
			end := off + n
			if end > len(data) {
				end = len(data)
			}
			clear(blk)
			copy(blk, data[off:end])
			m.b.Encrypt(h, z)
			acc.xor(gfMulBlock(h, blk))
			incrHalf(z[:n/2])
		}
	}
	absorb(a)
	absorb(c)

	// len(A) || len(C) — длины в битах, по половине блока каждая
	clear(blk)
	if n == 16 {
		binary.BigEndian.PutUint64(blk[0:8], uint64(len(a))*8)
		binary.BigEndian.PutUint64(blk[8:16], uint64(len(c))*8)
	} else {
		binary.BigEndian.PutUint32(blk[0:4], uint32(uint64(len(a))*8))
		binary.BigEndian.PutUint32(blk[4:8], uint32(uint64(len(c))*8))
	}
	m.b.Encrypt(h, z)
	acc.xor(gfMulBlock(h, blk))

	sum := acc.bytes(n)
	m.b.Encrypt(sum, sum)
	copy(out, sum[:m.tagSize])
}

// incrHalf прибавляет 1 к половине блока как к числу big-endian с переносом.
func incrHalf(half []byte) {
	for i := len(half) - 1; i >= 0; i-- {
		half[i]++
		if half[i] != 0 {
			return
		}
	}
}

// gfElem — элемент GF(2^64) или GF(2^128): hi — старшие 64 бита (для n=8 не используется).
type gfElem struct{ hi, lo uint64 }

func (e *gfElem) xor(o gfElem) { e.hi ^= o.hi; e.lo ^= o.lo }

func (e gfElem) bytes(n int) []byte {
	out := make([]byte, n)
	if n == 16 {
		binary.BigEndian.PutUint64(out[:8], e.hi)
		binary.BigEndian.PutUint64(out[8:], e.lo)
	} else {
		binary.BigEndian.PutUint64(out, e.lo)
	}
	return out
}

// gfMulBlock умножает два блока как многочлены над GF(2)
// (блок — число big-endian, бит i — коэффициент при x^i) по модулю
//
//	x^128 + x^7 + x^2 + x + 1  для n = 16,
//	x^64 + x^4 + x^3 + x + 1   для n = 8.
//
// Без ветвлений по данным: ключевые H_i секретны.
func gfMulBlock(a, b []byte) gfElem {
	if len(a) == 16 {
		ah, al := binary.BigEndian.Uint64(a[:8]), binary.BigEndian.Uint64(a[8:])
		bh, bl := binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])
		var zh, zl uint64
		for i := 127; i >= 0; i-- {
			// z = z·x mod p
			carry := zh >> 63
			zh = zh<<1 | zl>>63
			zl = zl<<1 ^ (0x87 & -carry)
			// если бит i множителя b равен 1: z ^= a
			var bit uint64
			if i >= 64 {
				bit = bh >> uint(i-64) & 1
			} else {
				bit = bl >> uint(i) & 1
			}
			mask := -bit
			zh ^= ah & mask
			zl ^= al & mask
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

// sliceForAppend — как в crypto/cipher: расширяет dst на n байт.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
