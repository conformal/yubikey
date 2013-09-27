// Copyright (c) 2013 Conformal Systems LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package yubikey

import (
	"bytes"
	"encoding/binary"
	"testing"
)

var aesEncodeTests = []struct {
	buf string
	key Key
	out string
}{
	{
		"0123456789abcdef",
		Key([KeySize]byte{
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x30, 0x31,
			0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
		}),
		"\x83\x8a\x46\x7f\x34\x63\x95\x51\x75\x5b\xd3\x2a\x4a\x2f\x15\xe1",
	},
	{
		"\x69\xb6\x48\x1c\x8b\xab\xa2\xb6\x0e\x8f\x22\x17\x9b\x58\xcd\x56",
		Key([KeySize]byte{
			0xec, 0xde, 0x18, 0xdb, 0xe7, 0x6f, 0xbd, 0x0c,
			0x33, 0x33, 0x0f, 0x1c, 0x35, 0x48, 0x71, 0xdb,
		}),
		"\x87\x92\xeb\xfe\x26\xcc\x13\x00\x30\xc2\x00\x11\xc8\x9f\x23\xc8",
	},
}

var crcTests = []struct {
	in  string
	out uint16
}{
	{"\x87\x92\xeb\xfe\x26\xcc\x13\x00\x30\xc2\x00\x11\xc8\x9f\x23\xc8", 61624},
}

var hexEncodeTests = []struct {
	in  string
	out string
}{
	{"test", "74657374"},
}

var hexPTests = []struct {
	in  string
	out bool
}{
	{"0123456789abcdef", true},
}

var modHexEncodeTests = []struct {
	in  string
	out string
}{
	{"test", "ifhgieif"},
	{"justanothergotest", "hligieifhbhuhvifhjhgidhihvifhgieif"},
}

var modHexPTests = []struct {
	in  string
	out bool
}{
	{"cbdefghijklnrtuv", true},
	{"0123Xabc", false},
}

var parseTests = []struct {
	token  string
	key    Key
	result []byte
}{
	{
		"dcflcindvdbrblehecuitvjkjevvehjd",
		Key([KeySize]byte{
			0xec, 0xde, 0x18, 0xdb, 0xe7, 0x6f, 0xbd, 0x0c,
			0x33, 0x33, 0x0f, 0x1c, 0x35, 0x48, 0x71, 0xdb,
		}),
		[]byte{
			0x87, 0x92, 0xeb, 0xfe, 0x26, 0xcc, 0x13, 0x00,
			0xa8, 0xc0, 0x00, 0x10, 0xb4, 0x08, 0x6f, 0x5b,
		},
	},
}

var otpTests = []struct {
	token []byte
	key   Key
}{
	{
		[]byte{
			0x16, 0xe1, 0xe5, 0xd9, 0xd3, 0x99, 0x10, 0x04,
			0x45, 0x20, 0x07, 0xe3, 0x02, 0x00, 0x00, 0x00,
		},
		Key([KeySize]byte{
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x30, 0x31,
			0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
		}),
	},
}

func TestAes(t *testing.T) {
	// Encrypt and Decrypt tests
	for x, test := range aesEncodeTests {
		// Encrypt tests
		buf := []byte(test.out)
		if res := AesEncrypt(buf, test.key); !bytes.Equal(res, []byte(test.buf)) {
			t.Errorf("AesEncrypt test #%d failed: got: %s want: %s",
				x, res, test.buf)
			continue
		}

		// Decrypt tests
		buf = []byte(test.buf)
		if res := AesDecrypt(buf, test.key); !bytes.Equal(res, []byte(test.out)) {
			t.Errorf("AesDecrypt test #%d failed: got: %s want: %s",
				x, res, test.out)
			continue
		}
	}
}

func TestCrc(t *testing.T) {
	for x, test := range crcTests {
		// Encode tests
		tmp := []byte(test.in)
		if res := Crc16(tmp); res != test.out {
			t.Errorf("Crc16 test #%d failed: got: %v want: %v",
				x, res, test.out)
			continue
		}
	}
}

func TestHex(t *testing.T) {
	// Encode and Decode tests
	for x, test := range hexEncodeTests {
		// Encode tests
		tmp := []byte(test.in)
		if res := HexEncode(tmp); !bytes.Equal(res, []byte(test.out)) {
			t.Errorf("HexEncode test #%d failed: got: %s want: %s",
				x, res, test.out)
			continue
		}
		// Decode tests
		tmp = []byte(test.out)
		if res := HexDecode(tmp); !bytes.Equal(res, []byte(test.in)) {
			t.Errorf("HexDecode test #%d failed: got: %s want: %s",
				x, res, test.in)
			continue
		}

	}
	for x, test := range hexPTests {
		tmp := []byte(test.in)
		if res := HexP(tmp); res != test.out {
			t.Errorf("HexP test #%d failed: got: %v want: %v",
				x, res, test.out)
			continue
		}
	}
}

func TestModHex(t *testing.T) {
	// Encode and Decode tests
	for x, test := range modHexEncodeTests {
		// Encode tests
		tmp := []byte(test.in)
		if res := ModHexEncode(tmp); !bytes.Equal(res, []byte(test.out)) {
			t.Errorf("ModeHexEncode test #%d failed: got: %s want: %s",
				x, res, test.out)
			continue
		}
		// Decode tests
		tmp = []byte(test.out)
		if res := ModHexDecode(tmp); string(res) != test.in {
			t.Errorf("ModeHexDecode test #%d failed: got: %v want: %v",
				x, string(res), test.in)
			continue
		}
	}

	// ModHexP tests
	for x, test := range modHexPTests {
		tmp := []byte(test.in)
		if res := ModHexP(tmp); res != test.out {
			t.Errorf("ModeHexP test #%d failed: got: %v want: %v",
				x, res, test.out)
			continue
		}
	}
}

func TestParse(t *testing.T) {
	for x, test := range parseTests {
		var buf1 bytes.Buffer
		if err := binary.Write(&buf1, binary.LittleEndian, []byte(test.token)); err != nil {
			t.Errorf("TestOtp test #%d failed: %v", x, err)
			continue
		}

		var otp OTP
		buf2 := bytes.NewBuffer(buf1.Bytes())
		if err := binary.Read(buf2, binary.LittleEndian, &otp); err != nil {
			t.Errorf("TestOtp test #%d failed: %v", x, err)
			continue
		}

		res, err := Parse(&otp, test.key)
		if err != nil {
			t.Errorf("TestOtp test #%d failed: %v", x, err)
			continue
		}

		var buf3 bytes.Buffer
		if err := binary.Write(&buf3, binary.LittleEndian, res); err != nil {
			t.Errorf("TestOtp test #%d failed: %v", x, err)
			continue
		}
		if !bytes.Equal(buf3.Bytes(), test.result) {
			t.Errorf("TestOtp test #%d failed: got: %x want: %x",
				x, buf3.Bytes(), test.result)
			continue
		}
	}
}

func TestOtp(t *testing.T) {
	for x, test := range otpTests {
		var token Token
		buf1 := bytes.NewBuffer(test.token)
		if err := binary.Read(buf1, binary.LittleEndian, &token); err != nil {
			t.Errorf("TestOtp test #%d failed: %v", x, err)
			continue
		}
		gen, err := Generate(token, test.key)
		if err != nil {
			t.Errorf("TestOtp test #%d failed: %v", x, err)
			continue
		}
		res, err := Parse(gen, test.key)
		if err != nil {
			t.Errorf("TestOtp test #%d failed: %v", x, err)
			continue
		}
		var buf2 bytes.Buffer
		if err := binary.Write(&buf2, binary.LittleEndian, res); err != nil {
			t.Errorf("TestOtp test #%d failed: %v", x, err)
			continue
		}
		if !bytes.Equal(test.token, buf2.Bytes()) {
			t.Errorf("TestOtp test #%d failed: got: %v want: %v",
				x, test.token, buf2.Bytes())
			continue
		}

	}
}
