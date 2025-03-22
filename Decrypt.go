package main

import (
	"bytes"
	"fmt"
)

func Decrypt(cipherText [][16]byte, t []byte, a []byte, key [32]byte, nonce [16]byte) (error, []byte, []byte) {
	c := &block{}
	aT := &block{}
	pT := &block{}

	h := pToBlock(a, aT)
	q, lenC, _ := trimTrailingZeros(cipherText, c)
	aBlock, lenA := getA(h, aT)
	lenAC := getLen(lenA, lenC)

	nonce0, nonce1 := concNonce(nonce)
	H := getH(h+1, q+1, nonce1, key)

	tNew := getT(H, cipherText, aBlock, key, s, h+1, q+1, lenAC)
	//fmt.Printf("%X\n", tNew)
	if !bytes.Equal(t, tNew) {
		return fmt.Errorf("ошибка проверки дополнительных имитозащищаемых данных"), nil, nil
	}

	y := getY(q+1, nonce0, key) //уже Ek

	pText := getPlainText(q, c, y)
	_, _, plainText := trimTrailingZeros(pText, pT)

	return nil, plainText, a

}

func trimTrailingZeros(blocks [][16]byte, p *block) (int, int, []byte) {
	q := len(blocks)

	p.b = blocks[:len(blocks)-1]
	lastBlock := blocks[len(blocks)-1][:]

	last := len(lastBlock) - 1

	for len(lastBlock) > 0 && lastBlock[last] == 0 {
		lastBlock = lastBlock[:last]
		last = len(lastBlock) - 1
	}
	p.bStar = lastBlock

	var result []byte
	for _, bl := range p.b {
		result = append(result, bl[:]...)
	}

	result = append(result, p.bStar...)

	return q - 1, (q-1)*16 + len(lastBlock), result
}

func getPlainText(q int, p *block, y [][16]byte) [][16]byte {
	plainText := make([][16]byte, q+1)

	for i := 0; i < q; i++ {
		copy(plainText[i][:], gfAdd(p.b[i][:], y[i][:]))
	}
	cStar := gfAdd(p.bStar, msb(y[q][:], len(p.bStar)))
	copy(plainText[q][:], cStar)

	return plainText
}

//func main() {
//	C := [][16]byte{{0xA9, 0x75, 0x7B, 0x81, 0x47, 0x95, 0x6E, 0x90, 0x55, 0xB8, 0xA3, 0x3D, 0xE8, 0x9F, 0x42, 0xFC},
//		{0x80, 0x75, 0xD2, 0x21, 0x2B, 0xF9, 0xFD, 0x5B, 0xD3, 0xF7, 0x06, 0x9A, 0xAD, 0xC1, 0x6B, 0x39},
//		{0x49, 0x7A, 0xB1, 0x59, 0x15, 0xA6, 0xBA, 0x85, 0x93, 0x6B, 0x5D, 0x0E, 0xA9, 0xF6, 0x85, 0x1C},
//		{0xC6, 0x0C, 0x14, 0xD4, 0xD3, 0xF8, 0x83, 0xD0, 0xAB, 0x94, 0x42, 0x06, 0x95, 0xC7, 0x6D, 0xEB},
//		{0x2C, 0x75, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
//
//	K := [32]byte{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
//		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
//
//	A := []byte{
//		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
//		0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
//		0xea, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05} //41
//
//	nonce := [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}
//
//	T := []byte{0xCF, 0x5D, 0x65, 0x6F, 0x40, 0xC3, 0x4F, 0x5C, 0x46, 0xE8, 0xBB, 0x0E, 0x29, 0xFC, 0xDB, 0x4C}
//
//	_, plainText, a := Decrypt(C, T, A, K, nonce)
//	fmt.Printf("plainText: %X\n", plainText)
//	fmt.Printf("a: %X\n", a)
//}
