package main

import (
	"flag"
	"fmt"
	"github.com/conformal/yubikey"
)

const (
	secretKey = "1585b014243c43360e3fe4d993c8b4c4"
)

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		usage()
		return
	}
	if len(args[0]) < 33 {
		fmt.Printf("OTP must be at least 33 characters\n")
		return
	}

	// The pass is the last 32 (OtpSize) bytes
	pass := args[0][len(args[0])-(yubikey.OtpSize):]

	otp := yubikey.NewOtp(pass)
	key := yubikey.NewKey(yubikey.HexDecode(secretKey))

	token, err := otp.Parse(key)
	if err != nil {
		fmt.Printf("yubikey.Parse error: %v\n", err)
		return
	}

	fmt.Printf("             uid: ")
	for _, val := range token.Uid {
		fmt.Printf("%02x ", val&0xFF)
	}
	fmt.Printf("\n")
	fmt.Printf(
		"         counter: %d (0x%04x)\n"+
			" timestamp (low): %d (0x%04x)\n"+
			"timestamp (high): %d (0x%02x)\n"+
			"     session use: %d (0x%02x)\n"+
			"          random: %d (0x%02x)\n"+
			"             crc: %d (0x%04x)\n",
		token.Ctr, token.Ctr,
		token.Tstpl, token.Tstpl,
		token.Tstph, token.Tstph,
		token.Use, token.Use,
		token.Rnd, token.Rnd,
		token.Crc, token.Crc)

	fmt.Printf("\nDerived:\n")
	fmt.Printf("       cleaned counter: %d (0x%04x)\n",
		token.Counter(), token.Counter())
	fmt.Printf("            modhex uid: %s\n", yubikey.ModHexEncode(token.Uid[:]))

	fmt.Printf("triggered by caps lock: %v\n", token.Capslock() == 0x8000)
	fmt.Printf("                   crc: %04X\n", token.Crc16())
	fmt.Printf("             crc check: %v\n", token.CrcOkP())
}

func usage() {
	fmt.Printf("usage: login.go <otp>\n")
}
