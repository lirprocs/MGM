package MGM

import (
	"encoding/binary"
	"fmt"
	"github.com/lirprocs/Kuznyechik/KuznEncrypt"
	"math"
)

const s = 16 //Длина имитовставки

type block struct {
	b     [][16]byte // Полные блокки
	bStar []byte     // Данные не вошедшие в блок
}

// Основная функция шифрования
func Encrypt(a []byte, pText []byte, key [32]byte, nonce [16]byte) (error, [][16]byte, []byte) {
	p := &block{}
	aT := &block{}
	q := pToBlock(pText, p) //Количество полных блоков
	h := pToBlock(a, aT)    //Количество полных блоков

	//Получение векторов 0||nonce и 1||nonce
	nonce0, nonce1 := concNonce(nonce)

	//Получение зашифрованных Y (Кузнечиком)
	y := getY(q+1, nonce0, key) //уже Ek
	//fmt.Printf("Y: %X\n", y)

	//Разделение A на блоки и получение размера A для вычисления T
	aBlock, lenA := getA(h, aT)

	//Разделение C на блоки и получение размера C для вычисления T
	c, lenC := getC(q, p, y)
	if len(pText)+lenA < 0 || float64(len(pText)+lenA) > math.Pow(2, 64) {
		return fmt.Errorf("Error of len"), nil, nil
	}

	//Вычисление Len(A)||Len(C)
	lenAC := getLen(lenA, lenC)

	//fmt.Printf("A: %X\n", aBlock)

	//Вычисление H
	H := getH(h+1, q+1, nonce1, key)
	//fmt.Printf("H: %X\n", H)

	//Вычисление T
	t := getT(H, c, aBlock, key, s, h+1, q+1, lenAC)
	//fmt.Printf("C: %X\n", c)
	//fmt.Printf("T: %X\n", t)
	return nil, c, t
}

func concNonce(nonce [16]byte) ([16]byte, [16]byte) {
	nonce0 := nonce
	nonce1 := nonce

	nonce0[0] = nonce0[0] & 0x7F
	nonce1[0] = nonce1[0] | 0x80

	return nonce0, nonce1
}

func pToBlock(pText []byte, plainText *block) int {
	var q int
	q = len(pText) / 16

	plainText.b = make([][16]byte, q)

	l, r := 0, 0
	for i := 0; i < q; i++ {
		l = r
		r = r + 16
		copy(plainText.b[i][:], pText[l:r])

	}
	plainText.bStar = pText[r:]
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

func getC(q int, p *block, y [][16]byte) ([][16]byte, int) {
	c := make([][16]byte, q+1)

	for i := 0; i < q; i++ {
		copy(c[i][:], gfAdd(p.b[i][:], y[i][:]))
	}
	cStar := gfAdd(p.bStar, msb(y[q][:], len(p.bStar)))
	copy(c[q][:], cStar)

	lenC := q*16 + len(cStar)
	return c, lenC
}

func getA(h int, p *block) ([][16]byte, int) {
	a := make([][16]byte, h+1)

	for i := 0; i < h; i++ {
		copy(a[i][:], p.b[i][:])
	}
	aStar := p.bStar
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

	//HA := sumHmulA(H, A, h)
	//HC := sumOfMul(H, C, q, h)
	//
	//HLen := gf128Mul(H[len(H)-1][:], lenAC)
	//fmt.Printf("F:%X\n", f)

	dataSlice := gfAdd(gfAdd(sumOfMul(H, A, h, 0), sumOfMul(H, C, q, h)), gf128Mul(H[len(H)-1][:], lenAC))
	//fmt.Printf("O+T+F:%X\n", dataSlice)
	copy(data[:], dataSlice[:])
	EkT := KuznEncrypt.Encrypt(data, key)
	return msb(EkT[:], s)
}

//func sumHmulA(H, A [][16]byte, h int) []byte {
//	var o []byte
//	HA := gf128Mul(H[0][:], A[0][:])
//	o = HA
//	for i := 1; i < h; i++ {
//		HA = gf128Mul(H[i][:], A[i][:])
//		o = gfAdd(o, HA)
//	}
//	//fmt.Printf("O:%X\n", o)
//	return o
//}

// Вспомогательная функция для вычисления T, считает суммы умнодения в поле GF
func sumOfMul(H, data [][16]byte, q, h int) []byte {
	var sum []byte
	HA := gf128Mul(H[h][:], data[0][:])
	sum = HA
	for j := 1; j < q; j++ {
		HA = gf128Mul(H[h+j][:], data[j][:])
		sum = gfAdd(sum, HA)
	}
	//fmt.Printf("Сумма сложения:%X\n", sum)
	return sum
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
	lenAC := make([]byte, 16) // Для 128-битного представления
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

//func main() {
//	//nonce := make([]byte, 16)
//	//_, err := rand.Read(nonce)
//	//if err != nil {
//	//	panic(err)
//	//}
//	//fmt.Printf("Nonce: %X\n", nonce)
//
//	nonce := [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}
//
//	K := [32]byte{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
//		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
//
//	A := []byte{
//		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
//		0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
//		0xea, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05} //41
//
//	P := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
//		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
//		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
//		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00, 0x11,
//		0xaa, 0xbb, 0xcc} //67
//
//	//A := []byte{}
//	//P := []byte{}
//
//	err, a, b := Encrypt(A, P, K, nonce)
//
//	fmt.Printf("Err: %s\n", err)
//	fmt.Printf("C: %X\n", a)
//	fmt.Printf("T: %X\n", b)
//}
