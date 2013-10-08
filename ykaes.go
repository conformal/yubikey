// Copyright (c) 2013 Conformal Systems LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package yubikey

import (
	"crypto/aes"
)

func AesDecrypt(src []byte, key Key) []byte {
	dst := make([]byte, len(src))
	cipher, _ := aes.NewCipher(key[:])
	cipher.Decrypt(dst, src)
	return dst

}

func AesEncrypt(src []byte, key Key) []byte {
	dst := make([]byte, len(src))
	cipher, _ := aes.NewCipher(key[:])
	cipher.Encrypt(dst, src)
	return dst
}
