package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/conformal/yubikey"
)

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 {
		usage()
		return
	}
	otp := yubikey.NewOTP(args[1])
	keyBytes, err := hex.DecodeString(args[0])
	if err != nil {
		fmt.Println("error decoding key:", err)
		return
	}
	key := yubikey.NewKey(keyBytes)

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

	fmt.Printf("triggered by caps lock: %v\n", token.Capslock())
	fmt.Printf("                   crc: %04X\n", token.Crc16())
	fmt.Printf("             crc check: %v\n", token.CrcOkP())
}

func usage() {
	fmt.Printf("usage: parse <aeskey> <token>\n" +
		"\taeskey: 32 character Hex encoded AES-key\n" +
		"\t token: 32 character ModHex encoded token\n")
}
