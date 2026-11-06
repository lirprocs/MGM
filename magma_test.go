package MGM

import (
	"encoding/binary"
	"fmt"
)

// Минимальная «Магма» (ГОСТ Р 34.12-2015, n = 64; RFC 8891) — только для тестов
// MGM с 64-битным блоком. Проверяется примером из RFC 8891 (TestMagmaBlockRFC8891).

var magmaPi = [8][16]byte{
	{12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
	{6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
	{11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
	{12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
	{7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
	{5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
	{8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
	{1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2},
}

type magmaCipher struct{ k [8]uint32 }

func newMagmaCipher(key []byte) (*magmaCipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("ключ Магмы — 32 байта")
	}
	c := &magmaCipher{}
	for i := range c.k {
		c.k[i] = binary.BigEndian.Uint32(key[4*i:])
	}
	return c, nil
}

func magmaG(k, a uint32) uint32 {
	x := a + k
	var y uint32
	for i := 0; i < 8; i++ {
		y |= uint32(magmaPi[i][(x>>(4*i))&15]) << (4 * i)
	}
	return y<<11 | y>>21
}

func (c *magmaCipher) BlockSize() int { return 8 }

func (c *magmaCipher) crypt(dst, src []byte, keys [32]uint32) {
	a1, a0 := binary.BigEndian.Uint32(src[:4]), binary.BigEndian.Uint32(src[4:8])
	for i := 0; i < 31; i++ {
		a1, a0 = a0, magmaG(keys[i], a0)^a1
	}
	a1 ^= magmaG(keys[31], a0)
	binary.BigEndian.PutUint32(dst[:4], a1)
	binary.BigEndian.PutUint32(dst[4:8], a0)
}

func (c *magmaCipher) Encrypt(dst, src []byte) {
	var keys [32]uint32
	for i := 0; i < 24; i++ {
		keys[i] = c.k[i%8]
	}
	for i := 0; i < 8; i++ {
		keys[24+i] = c.k[7-i]
	}
	c.crypt(dst, src, keys)
}

func (c *magmaCipher) Decrypt(dst, src []byte) {
	var keys [32]uint32
	for i := 0; i < 8; i++ {
		keys[i] = c.k[i]
	}
	for i := 8; i < 32; i++ {
		keys[i] = c.k[7-(i%8)]
	}
	c.crypt(dst, src, keys)
}
