package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/lirprocs/Kuznyechik/KuznEncrypt"
)

type plainText struct {
	p     [][16]byte
	pStar []byte
}

func Encrypt(a []byte, pText []byte, key [32]byte) ([][16]byte, []byte) {
	p := &plainText{}
	aT := &plainText{}
	q := pToBlock(pText, p) //Количество полных блоков
	h := pToBlock(a, aT)

	s := 16 //TODO нормально получать S
	nonceq := make([]byte, 16)
	_, err := rand.Read(nonceq)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Nonce: %X\n", nonceq)

	nonce0 := [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}
	y := getY(q+1, nonce0, key) //уже Ek
	fmt.Printf("Y: %X\n", y)

	aBlock, lenA := getA(h, aT)
	c, lenC := getC(q, p, y)
	lenAC := getLen(lenA, lenC)
	fmt.Printf("C: %X\n", c)
	fmt.Printf("A: %X\n", aBlock)

	nonce1 := [16]byte{0x91, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}
	H := getH(h+1, q+1, nonce1, key)
	fmt.Printf("H: %X\n", H)

	t := getT(H, c, aBlock, key, s, h+1, q+1, lenAC)
	fmt.Printf("T: %X\n", t)
	return c, t
}

func pToBlock(pText []byte, plainText *plainText) int {
	var q int
	q = len(pText) / 16

	plainText.p = make([][16]byte, q)

	l, r := 0, 0
	for i := 0; i < q; i++ {
		l = r
		r = r + 16
		copy(plainText.p[i][:], pText[l:r])

	}
	plainText.pStar = pText[r:]
	return q
}

func getY(q int, nonce [16]byte, key [32]byte) [][16]byte {
	y := make([][16]byte, q)
	yEnc := make([][16]byte, q)
	y[0] = KuznEncrypt.Encrypt(nonce, key)
	yEnc[0] = KuznEncrypt.Encrypt(y[0], key)

	for i := 1; i < q; i++ {
		y[i] = incrR(y[i-1])
		yEnc[i] = KuznEncrypt.Encrypt(y[i], key)
	}
	return yEnc
}

func getC(q int, p *plainText, y [][16]byte) ([][16]byte, int) {
	c := make([][16]byte, q+1)

	for i := 0; i < q; i++ {
		copy(c[i][:], gfAdd(p.p[i][:], y[i][:]))
	}
	cStar := gfAdd(p.pStar, msb(y[q][:], len(p.pStar)))
	copy(c[q][:], cStar)

	lenC := q*16 + len(cStar)
	return c, lenC
}

func getA(h int, p *plainText) ([][16]byte, int) {
	a := make([][16]byte, h+1)

	for i := 0; i < h; i++ {
		copy(a[i][:], p.p[i][:])
	}
	aStar := p.pStar
	copy(a[h][:], aStar)

	lenA := h*16 + len(aStar)
	return a, lenA
}

func getH(h, q int, nonce [16]byte, key [32]byte) [][16]byte {
	z := make([][16]byte, h+q+1)
	hEnc := make([][16]byte, h+q+1)
	z[0] = KuznEncrypt.Encrypt(nonce, key)
	hEnc[0] = KuznEncrypt.Encrypt(z[0], key)
	//fmt.Printf("Z%d: %X\n", 0, z[0])

	for i := 1; i < h+q+1; i++ {
		z[i] = incrL(z[i-1])
		//fmt.Printf("Z%d: %X\n", i, z[i])
		hEnc[i] = KuznEncrypt.Encrypt(z[i], key)
	}
	return hEnc
}

func getT(H, C, A [][16]byte, key [32]byte, s, h, q int, lenAC []byte) []byte {
	var data [16]byte
	o := geto(H, A, h)
	t := gett(H, C, q, h)

	f := gf128Mul(H[len(H)-1][:], lenAC)
	fmt.Printf("F:%X\n", f)

	dataSlice := gfAdd(gfAdd(o, t), f)
	copy(data[:], dataSlice[:])
	Ek := KuznEncrypt.Encrypt(data, key)
	return msb(Ek[:], s)
}

func geto(H, A [][16]byte, h int) []byte {
	var o []byte
	HA := gf128Mul(H[0][:], A[0][:])
	o = HA
	for i := 1; i < h; i++ {
		HA = gf128Mul(H[i][:], A[i][:])
		o = gfAdd(o, HA)
	}
	fmt.Printf("O:%X\n", o)
	return o
}

func gett(H, C [][16]byte, q, h int) []byte {
	var t []byte
	HA := gf128Mul(H[h][:], C[0][:])
	t = HA
	for j := 1; j < q; j++ {
		HA = gf128Mul(H[h+j][:], C[j][:])
		t = gfAdd(t, HA)
	}
	fmt.Printf("T:%X\n", t)
	return t
}

func msb(data []byte, i int) []byte {
	return data[:i]
}

func incrR(nonce [16]byte) [16]byte {
	nonce[15] = nonce[15] + 1
	return nonce
}

func incrL(nonce [16]byte) [16]byte {
	nonce[7] = nonce[7] + 1
	return nonce
}

func getLen(lenA, lenC int) []byte {
	lenAC := make([]byte, 16) // Для 128-битного представления (например, если n = 128)
	binary.BigEndian.PutUint64(lenAC[:8], uint64(lenA)*8)
	binary.BigEndian.PutUint64(lenAC[8:], uint64(lenC)*8)
	return lenAC
}

func gfAdd(a, b []byte) []byte {
	ans := make([]byte, len(a))
	for k, v := range a {
		ans[k] = v ^ b[k]
	}
	return ans
}

func bytesToUint64(b []byte) (uint64, uint64) {
	var high, low uint64
	for i := 0; i < 8; i++ {
		high = (high << 8) | uint64(b[i])
		low = (low << 8) | uint64(b[i+8])
	}
	return high, low
}

func uint64ToBytes(high, low uint64) [16]byte {
	var b [16]byte
	for i := 0; i < 8; i++ {
		b[i] = byte(high >> (56 - 8*i))
		b[i+8] = byte(low >> (56 - 8*i))
	}
	return b
}

func gf128Mul(a, b []byte) []byte {
	var x [16]byte
	var aLow, aHigh = bytesToUint64(a[:])
	var bLow, bHigh = bytesToUint64(b[:])
	var xHigh, xLow uint64
	pow2_63 := uint64(0x8000000000000000) // 2^63
	var bitFlag uint64

	for bHigh != 0 || bLow != 0 {
		if bHigh&1 != 0 {
			xLow ^= aLow
			xHigh ^= aHigh
		}

		bitFlag = aHigh & pow2_63
		aHigh = (aHigh << 1) ^ (func() uint64 {
			if aLow&pow2_63 != 0 {
				return 0x87
			}
			return 0x00
		}())
		aLow = (aLow << 1) | (bitFlag >> 63)

		bitFlag = bLow & 0x01
		bHigh = (bHigh >> 1) | (bitFlag << 63)
		bLow = bLow >> 1
	}

	x = uint64ToBytes(xLow, xHigh)
	return x[:]
}

func main() {
	//O := "Привет мир"
	//fmt.Printf("Nonce: %X\n", []byte(O))
	//key := "keyя"
	//keyByte := []byte(key)
	//fmt.Printf("Nonce: %X\n", keyByte)
	//fmt.Print(len(keyByte))
	//if len(keyByte) < 32 {
	//	key += strings.Repeat("L", 32-len(keyByte))
	//	keyByte = []byte(key)
	//}
	//fmt.Printf("Nonce: %X\n", keyByte)
	//fmt.Print(len(keyByte))
	//
	//fmt.Printf("Nonce: %X\n", 0)
	//
	//h := make([]byte, 2)
	//fmt.Printf("Nonce: %X\n", h)
	//
	//fmt.Println(17/16 + 1)
	//fmt.Println(33/16 + 1)
	//fmt.Println(65/16 + 1)

	//a := []byte{5}
	//b := []byte{3}
	//fmt.Printf("%X", gfAdd(a, b))

	//a, _ := hex.DecodeString("AABBCCDDEEFF00112233445566778899")
	//b, _ := hex.DecodeString("112233445566778899AABBCCDDEEFF00")
	//
	//res := gf128Mul(a, b)
	//fmt.Printf("A ⊗ B (mod f(x)): %X\n", res)

	//key := [32]byte{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	//0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	//plainText := [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}
	//z := KuznEncrypt.Encrypt(plainText, key)
	//fmt.Printf("%X\n", z)

	K := [32]byte{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}

	//nonce0 := [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}
	//nonce1 := [16]byte{0x91, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}

	A := []byte{
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
		0xea, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05} //41

	P := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00, 0x11,
		0xaa, 0xbb, 0xcc} //67

	//P := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
	//	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
	//	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
	//	0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00, 0x11} //64

	//z1 := KuznEncrypt.Encrypt(nonce, K)
	//fmt.Printf("%X\n", z1)
	//
	//Encrypt(P, key)

	/*s := getY(5, nonce, K)

	fmt.Printf("%X\n", s)

	fmt.Printf("%X\n", msb(nonce[:], 4))*/

	//p := &plainText{}
	//
	//pToBlock(P, p)
	//
	//fmt.Printf("%X: %X", p.p, p.pStar)

	//i =
	//j =
	//h = 3
	//q = 5

	Encrypt(A, P, K)

	result := [16]byte{0xFD, 0x47, 0x5B, 0xCA, 0x28, 0x79, 0x55, 0x9B, 0x79, 0xF1, 0xF3, 0x57, 0xF2, 0xC3, 0x6E, 0x28}

	KuznEncrypt.Encrypt(result, K)
}
