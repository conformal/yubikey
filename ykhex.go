// Copyright (c) 2013 Conformal Systems LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package yubikey

import (
	"bytes"
)

const (
	HexMap = "0123456789abcdef"
)

func HexEncode(src []byte) []byte {
	dst := make([]byte, len(src)*2)
	idx := 0

	for _, val := range src {
		dst[idx] = HexMap[(val>>4)&0xf]
		dst[idx+1] = HexMap[val&0xf]
		idx += 2
	}
	return dst
}

func HexDecode(src []byte) []byte {
	dst := make([]byte, (len(src)+1)/2)
	idx := 0
	alt := false

	for _, val := range src {
		b := bytes.IndexByte([]byte(HexMap), val)
		if b == -1 {
			b = 0
		}
		bb := byte(b)

		alt = !alt
		if alt {
			dst[idx] = bb
		} else {
			dst[idx] <<= 4
			dst[idx] |= bb
			idx++
		}
	}

	return dst
}

func HexP(src []byte) bool {
	for _, val := range src {
		if bytes.IndexByte([]byte(HexMap), val) == -1 {
			return false
		}
	}
	return true
}
