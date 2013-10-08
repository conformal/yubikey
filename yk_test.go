// Copyright (c) 2013 Conformal Systems LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package yubikey

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

var aesEncodeTests = []struct {
	buf string
	key string
	out string
}{
	{
		"0123456789abcdef",
		"abcdef0123456789",
		"\x83\x8a\x46\x7f\x34\x63\x95\x51\x75\x5b\xd3\x2a\x4a\x2f\x15\xe1",
	},
	{
		"\x69\xb6\x48\x1c\x8b\xab\xa2\xb6\x0e\x8f\x22\x17\x9b\x58\xcd\x56",
		string([]byte{
			0xec, 0xde, 0x18, 0xdb, 0xe7, 0x6f, 0xbd, 0x0c,
			0x33, 0x33, 0x0f, 0x1c, 0x35, 0x48, 0x71, 0xdb,
		}),
		"\x87\x92\xeb\xfe\x26\xcc\x13\x00\x30\xc2\x00\x11\xc8\x9f\x23\xc8",
	},
}

var crcTests = []struct {
	in  []byte
	out uint16
}{
	{
		[]byte{
			0x87, 0x92, 0xeb, 0xfe, 0x26, 0xcc, 0x13, 0x00,
			0x30, 0xc2, 0x00, 0x11, 0xc8, 0x9f, 0x23, 0xc8,
		},
		61624,
	},
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
	{"6789abcdefghijkl", false},
}

var modHexEncodeTests = []struct {
	in  string
	out string
}{
	{"test", "ifhgieif"},
	{"justanothergotest", "hligieifhbhuhvifhjhgidhihvifhgieif"},
	{"foobar", "hhhvhvhdhbid"},
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
	key    string
	result []byte
}{
	{
		"dcflcindvdbrblehecuitvjkjevvehjd",
		string([]byte{
			0xec, 0xde, 0x18, 0xdb, 0xe7, 0x6f, 0xbd, 0x0c,
			0x33, 0x33, 0x0f, 0x1c, 0x35, 0x48, 0x71, 0xdb,
		}),
		[]byte{
			0x87, 0x92, 0xeb, 0xfe, 0x26, 0xcc, 0x13, 0x00,
			0xa8, 0xc0, 0x00, 0x10, 0xb4, 0x08, 0x6f, 0x5b,
		},
	},
	{
		"hknhfjbrjnlnldnhcujvddbikngjrtgh",
		string([]byte{
			0xec, 0xde, 0x18, 0xdb, 0xe7, 0x6f, 0xbd, 0x0c,
			0x33, 0x33, 0x0f, 0x1c, 0x35, 0x48, 0x71, 0xdb,
		}),
		[]byte{
			0x87, 0x92, 0xeb, 0xfe, 0x26, 0xcc, 0x13, 0x00,
			0x30, 0xc2, 0x00, 0x11, 0xc8, 0x9f, 0x23, 0xc8,
		},
	},
}

var otpTests = []struct {
	token    []byte
	key      []byte
	capslock bool
	counter  bool
	crc16    bool
}{
	{
		[]byte{
			0x16, 0xe1, 0xe5, 0xd9, 0xd3, 0x99, 0x10, 0x04,
			0x45, 0x20, 0x07, 0xe3, 0x02, 0x00, 0x22, 0x6d,
		},
		[]byte{
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x30, 0x31,
			0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
		},
		false,
		false,
		true,
	},
	{
		[]byte{
			0x16, 0xe1, 0xe5, 0xd9, 0xd3, 0x99, 0x81, 0xab,
			0x45, 0x20, 0x07, 0xe3, 0x02, 0x00, 0x6d, 0x80,
		},
		[]byte{
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x30, 0x31,
			0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
		},
		true,
		false,
		true,
	},
	{
		[]byte{
			0x16, 0xe1, 0xe5, 0xd9, 0xd3, 0x99, 0xff, 0x7f,
			0x45, 0x20, 0x07, 0xe3, 0x02, 0x00, 0xbd, 0xa3,
		},
		[]byte{
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x30, 0x31,
			0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
		},
		false,
		true,
		true,
	},
}

func TestAes(t *testing.T) {
	// Encrypt and Decrypt tests
	for x, test := range aesEncodeTests {
		// Encrypt tests
		key := NewKey(test.key)
		if res := AesEncrypt([]byte(test.out), key); !bytes.Equal(res, []byte(test.buf)) {
			t.Errorf("AesEncrypt test #%d failed: got: %s want: %s",
				x, res, test.buf)
			continue
		}

		// Decrypt tests
		if res := AesDecrypt([]byte(test.buf), key); !bytes.Equal(res, []byte(test.out)) {
			t.Errorf("AesDecrypt test #%d failed: got: %s want: %s",
				x, res, test.out)
			continue
		}
	}
}

func TestCapslock(t *testing.T) {
	for x, test := range otpTests {
		token, err := NewTokenFromBytes(test.token)
		if err != nil {
			t.Errorf("Capslock test #%d failed: %v", x, err)
			continue
		}

		res := token.Capslock() == 0x8000
		if res != test.capslock {
			t.Errorf("Capslock test #%d failed: got: %v want: %v",
				x, res, test.capslock)
		}

	}
}

func TestCounter(t *testing.T) {
	for x, test := range otpTests {
		token, err := NewTokenFromBytes(test.token)
		if err != nil {
			t.Errorf("Counter test #%d failed: %v", x, err)
			continue
		}

		res := token.Counter() == 0x7fff
		if res != test.counter {
			t.Errorf("Counter test #%d failed: got: %v want: %v",
				x, res, test.counter)
		}
	}
}

func TestCrc(t *testing.T) {
	for x, test := range crcTests {
		token, err := NewTokenFromBytes(test.in)
		if err != nil {
			t.Errorf("Crc16 test #%d failed: %v\n", x, err)
			continue
		}

		if res := token.Crc16(); res != test.out {
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
		if res := HexEncode(test.in); res != test.out {
			t.Errorf("HexEncode test #%d failed: got: %s want: %s",
				x, res, test.out)
			continue
		}
		// Decode tests
		if res := HexDecode(test.out); res != test.in {
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
		if res := ModHexEncode([]byte(test.in)); !bytes.Equal(res, []byte(test.out)) {
			t.Errorf("ModeHexEncode test #%d failed: got: %s want: %s",
				x, res, test.out)
			continue
		}
		// Decode tests
		if res := ModHexDecode([]byte(test.out)); !bytes.Equal(res, []byte(test.in)) {
			t.Errorf("ModeHexDecode test #%d failed: got: %v want: %v",
				x, res, test.in)
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
		otp := NewOtp(test.token)
		key := NewKey(test.key)
		res, err := otp.Parse(key)
		if err != nil {
			t.Errorf("TestParse test #%d failed: %v", x, err)
			continue
		}

		buf := res.Bytes()

		if !bytes.Equal(buf, test.result) {
			t.Errorf("TestParse test #%d failed: got: %x want: %x",
				x, buf, test.result)
			continue
		}
	}
}

func TestOtp(t *testing.T) {
	for x, test := range otpTests {
		token, err := NewTokenFromBytes(test.token)
		if err != nil {
			t.Errorf("TestOtp test #%d failed: %v", x, err)
			continue
		}
		key := NewKey(string(test.key))
		otp := token.Generate(key)

		res, err := otp.Parse(key)
		if err != nil {
			t.Errorf("TestOtp test #%d failed: %v", x, err)
			continue
		}
		buf := res.Bytes()

		if !bytes.Equal(test.token, buf) {
			t.Errorf("TestOtp test #%d failed: got: %v want: %v",
				x, test.token, buf)
			continue
		}

	}
}

func TestNewToken(t *testing.T) {

	// sample key from test-vectors.txt
	uid, _ := hex.DecodeString("8792ebfe26cc")

	token := NewToken(NewUid(string(uid)), 19, 49712, 0, 17, 40904)

	var u Uid
	copy(u[:], uid)

	tok := &Token{Uid: u, Ctr: 19, Tstpl: 49712, Tstph: 0, Use: 17, Rnd: 40904, Crc: 51235}

	if !reflect.DeepEqual(tok, token) {
		t.Errorf("TestNewToken failed: got=%#v wanted=%#v", token, tok)
	}
}
