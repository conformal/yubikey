// Copyright (c) 2013 Conformal Systems LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package yubikey

import (
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

// Key represents the symmetric 128-bit AES Key
type Key [KeySize]byte

// OTP represents the One Time Password
type OTP [OtpSize]byte

// Uid represents the Private (secret) id.
type Uid [UidSize]byte

// Token represents the YubiKey token structure.
type Token struct {
	Uid   Uid
	Ctr   uint16
	Tstpl uint16
	Tstph uint8
	Use   uint8
	Rnd   uint16
	Crc   uint16
}

var (
	ErrCrcFailure = errors.New("CRC failure")
)

// NewToken is a helper function to create a new Token.
// The CRC is calculated for the caller.
func NewToken(uid Uid, ctr, tstpl uint16, tstph,
	use uint8, rnd uint16) *Token {
	token := Token{
		Uid:   uid,
		Ctr:   ctr,
		Tstpl: tstpl,
		Tstph: tstph,
		Use:   use,
		Rnd:   rnd,
	}

	// Calculate CRC
	buf := token.Bytes()

	token.Crc = ^crc16(buf[:14])

	return &token
}

// NewTokenFromBytes converts a byte stream into a Token.
// An error will be returned on a CRC failure.
func NewTokenFromBytes(buf []byte) (*Token, error) {
	var token Token

	// This goes first to avoid buf->token->buf dance that would happen if it was at the end
	if len(buf) != 16 && !Crc16BufOkP(buf) {
		return nil, ErrCrcFailure
	}

	copy(token.Uid[:], buf[:6])

	token.Ctr = binary.LittleEndian.Uint16(buf[6:])
	token.Tstpl = binary.LittleEndian.Uint16(buf[8:])

	token.Tstph = buf[10]
	token.Use = buf[11]

	token.Rnd = binary.LittleEndian.Uint16(buf[12:])
	token.Crc = binary.LittleEndian.Uint16(buf[14:])

	return &token, nil
}

// Generate encrypts a Token with the specified Key
// and returns a OTP.
func (t *Token) Generate(key Key) *OTP {
	buf := t.Bytes()

	aesenc := AesEncrypt(buf, key)
	modenc := ModHexEncode(aesenc)

	var o OTP
	copy(o[:], modenc)

	return &o
}

func (t *Token) Capslock() uint16 {
	return t.Ctr & 0x8000
}

func (t *Token) Counter() uint16 {
	return t.Ctr & 0x7fff
}

func (t *Token) CrcOkP() bool {
	return t.Crc16() == CrcOkResidue
}

// Crc16 returns the CRC associated with the Token.
func (t *Token) Crc16() uint16 {
	buf := t.Bytes()

	return crc16(buf)
}

func Crc16BufOkP(buf []byte) bool {
	return crc16(buf) == CrcOkResidue
}

func crc16(buf []byte) uint16 {
	m_crc := uint16(0xffff)
	for _, val := range buf {
		m_crc ^= uint16(val & 0xff)
		for i := 0; i < 8; i++ {
			j := m_crc & 1
			m_crc >>= 1
			if j > 0 {
				m_crc ^= 0x8408
			}
		}
	}

	return m_crc
}

// Bytes returns the byte stream associated with
// the Token.
func (t *Token) Bytes() []byte {
	buf := make([]byte, 16)

	copy(buf[:6], t.Uid[:])
	binary.LittleEndian.PutUint16(buf[6:], t.Ctr)
	binary.LittleEndian.PutUint16(buf[8:], t.Tstpl)
	buf[10] = t.Tstph
	buf[11] = t.Use
	binary.LittleEndian.PutUint16(buf[12:], t.Rnd)
	binary.LittleEndian.PutUint16(buf[14:], t.Crc)

	return buf
}

// NewKey the specified string to a Key structure.
func NewKey(buf string) Key {
	var key Key
	copy(key[:], buf)

	return key
}

// NewOTP converts a string into an OTP structure.
func NewOtp(buf string) OTP {
	var otp OTP
	copy(otp[:], buf)

	return otp
}

// Parse decodes and decrypts the OTP with the specified Key
// returning a Token.
func (o OTP) Parse(key Key) (*Token, error) {
	buf := o.Bytes()

	moddec := ModHexDecode(buf)
	aesdec := AesDecrypt(moddec, key)

	token, err := NewTokenFromBytes(aesdec)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// Bytes returns the byte stream associated with
// the OTP.
func (o OTP) Bytes() []byte {
	buf := make([]byte, len(o))
	copy(buf, o[:])

	return buf
}

// NewUid returns a UID structure.
func NewUid(buf string) Uid {
	var uid Uid
	copy(uid[:], buf)

	return uid
}
