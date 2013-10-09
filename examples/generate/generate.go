package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/conformal/yubikey"
	"math/rand"
	"strconv"
	"time"
)

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) != 6 {
		usage()
		return
	}

	keyBytes, err := hex.DecodeString(args[0])
	if err != nil {
		fmt.Println("error decoding key:", err)
		return
	}
	key := yubikey.NewKey(keyBytes)
	uidBytes, _ := hex.DecodeString(args[1])
	if err != nil {
		fmt.Println("error decoding uid:", err)
		return
	}
	uid := yubikey.NewUid(uidBytes)

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

	token := yubikey.NewToken(uid, uint16(ctr), uint16(tstpl),
		uint8(tstph), uint8(use), rnd)

	otp := token.Generate(key)

	str := otp.Bytes()
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
