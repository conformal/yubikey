// Copyright (c) 2013 Conformal Systems LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package yubikey

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const (
	BlockSize    = 16
	KeySize      = 16
	OtpSize      = 32 // BlockSize * 2
	UidSize      = 6
	CrcOkResidue = 0xf0b8
)

// The supplied OTP was corrupt
var ErrCorruptOTP = errors.New("yubikey: corrupt otp")

type Key [KeySize]byte
type OTP [OtpSize]byte
type Uid [UidSize]byte

type Token struct {
	Uid   Uid
	Ctr   uint16
	Tstpl uint16
	Tstph uint8
	Use   uint8
	Rnd   uint16
	Crc   uint16
}

func Generate(token Token, key Key) (*OTP, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, token); err != nil {
		return nil, err
	}

	aesenc := AesEncrypt(buf.Bytes(), key)
	modenc := ModHexEncode(aesenc)

	var o OTP
	copy(o[:], modenc)

	return &o, nil
}

func Capslock(ctr uint16) uint16 {
	return ctr & 0x8000
}

func Counter(ctr uint16) uint16 {
	return ctr & 0x7FFF
}

func CrcOkP(token []byte) bool {
	return Crc16(token) == CrcOkResidue
}

func Parse(otp *OTP, key Key) (*Token, error) {

	moddec := ModHexDecode((*otp)[:])
	aesdec := AesDecrypt(moddec, key)

	if !CrcOkP(aesdec) {
		return nil, ErrCorruptOTP
	}

	aesdecReader := bytes.NewBuffer(aesdec)

	var token Token
	if err := binary.Read(aesdecReader, binary.LittleEndian, &token); err != nil {
		return nil, err
	}
	return &token, nil
}
