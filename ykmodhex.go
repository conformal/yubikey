// Copyright (c) 2013 Conformal Systems LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package yubikey

import (
	"bytes"
)

const (
	ModHexMap = "cbdefghijklnrtuv"
)

func ModHexEncode(src []byte) []byte {
	dst := make([]byte, len(src)*2)
	dstidx := 0

	for _, val := range src {
		dst[dstidx] = ModHexMap[(val>>4)&0xf]
		dst[dstidx+1] = ModHexMap[val&0xf]
		dstidx += 2
	}
	return dst
}

func ModHexDecode(src []byte) []byte {
	dst := make([]byte, (len(src)+1)/2)
	alt := false
	idx := 0

	for _, val := range src {
		b := bytes.IndexByte([]byte(ModHexMap), val)
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

func ModHexP(src []byte) bool {
	for _, val := range src {
		if bytes.IndexByte([]byte(ModHexMap), val) == -1 {
			return false
		}
	}
	return true
}
