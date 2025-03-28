package MGM

import (
	"bytes"
	"testing"
)

func TestConcNonce(t *testing.T) {
	tests := []struct {
		nonce, nonce0, nonce1 [16]byte
	}{
		{[16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88},
			[16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88},
			[16]byte{0x91, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}},
	}
	for _, tt := range tests {
		res0, res1 := concNonce(tt.nonce)
		if res0 != tt.nonce0 && res1 != tt.nonce1 {
			t.Errorf("concNonce0() = %X; want %X \n concNonce1() = %X; want %X \n", res0, tt.nonce0, res1, tt.nonce1)
		}
	}
}

func TestPToBlock(t *testing.T) {
	tests := []struct {
		input    []byte
		expected int
		bStar    []byte
	}{
		{
			input: []byte{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
				0xea, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05},
			expected: 2,
			bStar:    []byte{0xea, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05},
		},
		{
			input: []byte{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03},
			expected: 2,
			bStar:    []byte{},
		},
		{
			input: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
				0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00, 0x11,
				0xaa, 0xbb, 0xcc},
			expected: 4,
			bStar:    []byte{0xaa, 0xbb, 0xcc},
		},
		{
			input: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
				0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00, 0x11},
			expected: 4,
			bStar:    []byte{},
		},
	}

	for _, tt := range tests {
		plainText := &block{}
		result := pToBlock(tt.input, plainText)

		if result != tt.expected {
			t.Errorf("expected %d blocks, got %d", tt.expected, result)
		}

		if !bytes.Equal(plainText.bStar, tt.bStar) {
			t.Errorf("expected bStar %v, got %v", tt.bStar, plainText.bStar)
		}

		for i := 0; i < tt.expected; i++ {
			expectedBlock := tt.input[i*16 : (i+1)*16]
			if !bytes.Equal(plainText.b[i][:], expectedBlock) {
				t.Errorf("expected block %d: %v, got %v", i, expectedBlock, plainText.b[i][:])
			}
		}
	}
}

func TestGetY(t *testing.T) {
	tests := []struct {
		q        int
		nonce0   [16]byte
		key      [32]byte
		expected [][16]byte
	}{
		{
			5,
			[16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88},
			[32]byte{
				0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			},
			[][16]byte{
				{0xB8, 0x57, 0x48, 0xC5, 0x12, 0xF3, 0x19, 0x90, 0xAA, 0x56, 0x7E, 0xF1, 0x53, 0x35, 0xDB, 0x74},
				{0x80, 0x64, 0xF0, 0x12, 0x6F, 0xAC, 0x9B, 0x2C, 0x5B, 0x6E, 0xAC, 0x21, 0x61, 0x2F, 0x94, 0x33},
				{0x58, 0x58, 0x82, 0x1D, 0x40, 0xC0, 0xCD, 0x0D, 0x0A, 0xC1, 0xE6, 0xC2, 0x47, 0x09, 0x8F, 0x1C},
				{0xE4, 0x3F, 0x50, 0x81, 0xB5, 0x8F, 0x0B, 0x49, 0x01, 0x2F, 0x8E, 0xE8, 0x6A, 0xCD, 0x6D, 0xFA},
				{0x86, 0xCE, 0x9E, 0x2A, 0x0A, 0x12, 0x25, 0xE3, 0x33, 0x56, 0x91, 0xB2, 0x0D, 0x5A, 0x33, 0x48},
			},
		},
	}

	for _, tt := range tests {
		result := getY(tt.q, tt.nonce0, tt.key)
		for k, v := range result {
			if v != tt.expected[k] {
				t.Errorf("getY() = %X; want %X", v, tt.expected[k])
			}
		}
	}
}

func TestGetH(t *testing.T) {
	tests := []struct {
		h        int
		q        int
		nonce1   [16]byte
		key      [32]byte
		expected [][16]byte
	}{
		{
			3,
			5,
			[16]byte{0x91, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88},
			[32]byte{
				0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			},
			[][16]byte{
				{0x8D, 0xB1, 0x87, 0xD6, 0x53, 0x83, 0x0E, 0xA4, 0xBC, 0x44, 0x64, 0x76, 0x95, 0x2C, 0x30, 0x0B},
				{0x7A, 0x24, 0xF7, 0x26, 0x30, 0xE3, 0x76, 0x37, 0x21, 0xC8, 0xF3, 0xCD, 0xB1, 0xDA, 0x0E, 0x31},
				{0x44, 0x11, 0x96, 0x21, 0x17, 0xD2, 0x06, 0x35, 0xC5, 0x25, 0xE0, 0xA2, 0x4D, 0xB4, 0xB9, 0x0A},
				{0xD8, 0xC9, 0x62, 0x3C, 0x4D, 0xBF, 0xE8, 0x14, 0xCE, 0x7C, 0x1C, 0x0C, 0xEA, 0xA9, 0x59, 0xDB},
				{0xA5, 0xE1, 0xF1, 0x95, 0x33, 0x3E, 0x14, 0x82, 0x96, 0x99, 0x31, 0xBF, 0xBE, 0x6D, 0xFD, 0x43},
				{0xB4, 0xCA, 0x80, 0x8C, 0xAC, 0xCF, 0xB3, 0xF9, 0x17, 0x24, 0xE4, 0x8A, 0x2C, 0x7E, 0xE9, 0xD2},
				{0x72, 0x90, 0x8F, 0xC0, 0x74, 0xE4, 0x69, 0xE8, 0x90, 0x1B, 0xD1, 0x88, 0xEA, 0x91, 0xC3, 0x31},
				{0x23, 0xCA, 0x27, 0x15, 0xB0, 0x2C, 0x68, 0x31, 0x3B, 0xFD, 0xAC, 0xB3, 0x9E, 0x4D, 0x0F, 0xB8},
				{0xBC, 0xBC, 0xE6, 0xC4, 0x1A, 0xA3, 0x55, 0xA4, 0x14, 0x88, 0x62, 0xBF, 0x64, 0xBD, 0x83, 0x0D},
			},
		},
	}

	for _, tt := range tests {
		result := getH(tt.h, tt.q, tt.nonce1, tt.key)
		for k, v := range tt.expected {
			if v != result[k] {
				t.Errorf("getH() = %X; want %X", v, tt.expected[k])
			}
		}
	}
}

func TestEncrypt(t *testing.T) {
	tests := []struct {
		a         []byte
		pText     []byte
		key       [32]byte
		nonce     [16]byte
		expectedC [][16]byte
		expectedT []byte
	}{
		{
			[]byte{
				0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
				0xea, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05},
			[]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
				0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00, 0x11,
				0xaa, 0xbb, 0xcc},
			[32]byte{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
			[16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88},
			[][16]byte{{0xA9, 0x75, 0x7B, 0x81, 0x47, 0x95, 0x6E, 0x90, 0x55, 0xB8, 0xA3, 0x3D, 0xE8, 0x9F, 0x42, 0xFC},
				{0x80, 0x75, 0xD2, 0x21, 0x2B, 0xF9, 0xFD, 0x5B, 0xD3, 0xF7, 0x06, 0x9A, 0xAD, 0xC1, 0x6B, 0x39},
				{0x49, 0x7A, 0xB1, 0x59, 0x15, 0xA6, 0xBA, 0x85, 0x93, 0x6B, 0x5D, 0x0E, 0xA9, 0xF6, 0x85, 0x1C},
				{0xC6, 0x0C, 0x14, 0xD4, 0xD3, 0xF8, 0x83, 0xD0, 0xAB, 0x94, 0x42, 0x06, 0x95, 0xC7, 0x6D, 0xEB},
				{0x2C, 0x75, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			[]byte{0xCF, 0x5D, 0x65, 0x6F, 0x40, 0xC3, 0x4F, 0x5C, 0x46, 0xE8, 0xBB, 0x0E, 0x29, 0xFC, 0xDB, 0x4C},
		},
	}
	for _, tt := range tests {
		_, resC, resT := Encrypt(tt.a, tt.pText, tt.key, tt.nonce)
		if !bytes.Equal(resT, tt.expectedT) {
			t.Errorf("Encrypt() T = %X; want %X", resT, tt.expectedT)
		}
		for k, v := range resC {
			if v != tt.expectedC[k] {
				t.Errorf("Encrypt() TC = %X; want %X", v, tt.expectedC[k])
			}
		}

	}
}

func TestDecrypt(t *testing.T) {
	tests := []struct {
		a         []byte
		pText     []byte
		key       [32]byte
		nonce     [16]byte
		expectedC [][16]byte
		expectedT []byte
	}{
		{
			[]byte{
				0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
				0xea, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05},
			[]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
				0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00, 0x11,
				0xaa, 0xbb, 0xcc},
			[32]byte{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
			[16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88},
			[][16]byte{{0xA9, 0x75, 0x7B, 0x81, 0x47, 0x95, 0x6E, 0x90, 0x55, 0xB8, 0xA3, 0x3D, 0xE8, 0x9F, 0x42, 0xFC},
				{0x80, 0x75, 0xD2, 0x21, 0x2B, 0xF9, 0xFD, 0x5B, 0xD3, 0xF7, 0x06, 0x9A, 0xAD, 0xC1, 0x6B, 0x39},
				{0x49, 0x7A, 0xB1, 0x59, 0x15, 0xA6, 0xBA, 0x85, 0x93, 0x6B, 0x5D, 0x0E, 0xA9, 0xF6, 0x85, 0x1C},
				{0xC6, 0x0C, 0x14, 0xD4, 0xD3, 0xF8, 0x83, 0xD0, 0xAB, 0x94, 0x42, 0x06, 0x95, 0xC7, 0x6D, 0xEB},
				{0x2C, 0x75, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			[]byte{0xCF, 0x5D, 0x65, 0x6F, 0x40, 0xC3, 0x4F, 0x5C, 0x46, 0xE8, 0xBB, 0x0E, 0x29, 0xFC, 0xDB, 0x4C},
		},
	}
	for _, tt := range tests {
		_, c, TOld := Encrypt(tt.a, tt.pText, tt.key, tt.nonce)
		err, plainText, _ := Decrypt(c, TOld, tt.a, tt.key, tt.nonce)
		if err != nil {
			t.Errorf("Decrypt() T %e\n", err)
		}
		if !bytes.Equal(tt.pText, plainText) {
			t.Errorf("Decrypt() %X; want %X", plainText, tt.pText)
		}
		err, _, _ = Decrypt(c, tt.expectedT, tt.a, tt.key, tt.nonce)
		if err != nil {
			t.Errorf("Decrypt() T %e\n", err)
		}
	}
}

//h = 3
//q = 5

//K := [32]byte{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
//	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
//nonce := [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}
//nonce0 := [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}
//nonce1 := [16]byte{0x91, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}

//A := []byte{
//	0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
//	0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
//	0xea, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05} //41
//
//P := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
//	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
//	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
//	0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00, 0x11,
//	0xaa, 0xbb, 0xcc} //67

//P := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
//	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
//	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
//	0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00, 0x11} //64
