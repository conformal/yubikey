// Copyright (c) 2013 Conformal Systems LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package yubikey

func Crc16(buf []byte) uint16 {
	var m_crc uint16

	m_crc = 0xffff
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
