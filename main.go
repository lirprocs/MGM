package main

import (
	"crypto/rand"
	"fmt"
	"github.com/lirprocs/Kuznyechik/KuznEncrypt"
	"time"
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

	s := 32 //TODO нормально получать S
	nonceq := make([]byte, 16)
	_, err := rand.Read(nonceq)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Nonce: %X\n", nonceq)

	nonce0 := [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}
	y := getY(q+1, nonce0, key) //уже Ek
	fmt.Printf("Y: %X\n", y)

	c := getC(q, p, y)
	fmt.Printf("C: %X\n", c)

	nonce1 := [16]byte{0x91, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}
	H := getH(h+1, q+1, nonce1, key)
	fmt.Printf("H: %X\n", H)

	t := getT(H, c, a, key, s)
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

func getC(q int, p *plainText, y [][16]byte) [][16]byte {
	c := make([][16]byte, q+1)

	for i := 0; i < q; i++ {
		copy(c[i][:], gfAdd(p.p[i][:], y[i][:]))
	}
	copy(c[q][:], gfAdd(p.pStar, msb(y[q][:], len(p.pStar))))
	return c
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

func getT(h, c, a [][16]byte, key [32]byte, s int) []byte {
	var data [16]byte
	o :=
	t :=
	f :=

	dataSlice := gfAdd(gfAdd(o, t), f)
	copy(data[:], dataSlice[:])
	Ek := KuznEncrypt.Encrypt(data,key)
	return msb(Ek[:], s)
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

func gfAdd(a, b []byte) []byte {
	ans := make([]byte, len(a))
	for k, v := range a {
		ans[k] = v ^ b[k]
	}
	return ans
}

func gf128Mul(a, b []byte) []byte {
	const poly = 135 // Коэффициенты порождающего многочлена x⁷ + x² + x + 1 (1000 0111)
	res := make([]byte, 16)

	for i := 0; i < 16; i++ {
		for j := 0; j < 8; j++ {
			if (b[i] & (1 << (7 - j))) != 0 {
				res = gfAdd(res, a)
			}

			msbb := a[0] & 0x80

			for k := 0; k < 15; k++ {
				a[k] = (a[k] << 1) | (a[k+1] >> 7)
			}

			a[15] <<= 1
			if msbb != 0 {
				a[15] ^= poly
			}
		}
	}
	return res
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

	//nonce := [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}

	A := []byte{
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
		0xea, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05}

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

	Encrypt(A, P, K)

}
