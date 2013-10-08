package main

import (
	"flag"
	"fmt"
	"math/rand"
	"strconv"
	"time"
	"yubikey"
)

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) != 6 {
		usage()
		return
	}

	key := yubikey.NewKey(yubikey.HexDecode(args[0]))
	uid := yubikey.NewUid(yubikey.HexDecode(args[1]))

	ctr, err := strconv.Atoi(args[2])
	if err != nil {
		fmt.Printf("ctr error: %v\n", err)
		return
	}

	tstpl, err := strconv.Atoi(args[3])
	if err != nil {
		fmt.Printf("tstpl error: %v\n", err)
		return
	}

	tstph, err := strconv.Atoi(args[4])
	if err != nil {
		fmt.Printf("tstph error: %v\n", err)
		return
	}

	use, err := strconv.Atoi(args[5])
	if err != nil {
		fmt.Printf("use error: %v\n", err)
		return
	}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	rnd := uint16(r.Int())

	token, err := yubikey.NewToken(uid, uint16(ctr), uint16(tstpl),
		uint8(tstph), uint8(use), rnd)
	if err != nil {
		fmt.Printf("TokenNew error: %v\n", err)
		return
	}

	otp, err := token.Generate(key)
	if err != nil {
		fmt.Printf("yubikey.Generate error: %v\n", err)
		return
	}

	str, err := otp.Bytes()
	if err != nil {
		fmt.Printf("otp.Serialize error: %v\n", err)
	}
	fmt.Printf("%s\n", string(str))
}

func usage() {
	fmt.Printf("usage: parse <aeskey> <internalname> <counter> <low> <hi> <use>\n" +
		"\t       aeskey: Hex encoded AES-key\n" +
		"\t internalname: Hex encoded internal name (48 bit)\n" +
		"\t      counter: Hex encoded counter (16 bit)\n" +
		"\t          low: Hex encoded timestamp low (16 bit)\n" +
		"\t         high: Hex encoded timestamp high (8 bit)\n" +
		"\t          use: Hex encoded use (8 bit)\n")
}
