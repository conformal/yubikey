yubikey
=======

[![Build Status](https://travis-ci.org/conformal/yubikey.png?branch=master)](https://travis-ci.org/conformal/yubikey)

Package yubikey implements the [Yubico](http://www.yubico.com) [YubiKey](http://www.yubico.com/products/yubikey-hardware/) API.

## Example

The package needs to know the secret key of the YubiKey token; this
may be stored as a string. For example, the secret key could be
loaded from a file with:

```go
import (
	"bytes"
	"encoding/hex"
	"github.com/conformal/yubikey"
	"io/ioutil"
)

func LoadSecretKey(filename string) (*Key, error) {
	in, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	in, err = bytes.TrimSpace(in)
	if err != nil {
		return nil, err
	}

	keyBytes := make([]byte, len(in) / 2)
	err = hex.Decode(keyBytes, in)
	if err != nil {
		return nil, err
	}

	priv := yubikey.NewKey(keyBytes)
	return priv, nil
}
```

Then, you can pass the OTP string directly from the YubiKey to
`ParseOTPString`:

```go
	func GetToken(otpString string, priv *Key) (*Token, error) {
		pub, otp, err := yubikey.ParseOTPString(otpString)
		if err != nil {
			return nil, err
		}

	        keyBytes, err := hex.DecodeString(secretKey)
		if err != nil {
			return nil, err
		}
		t, err := otp.Parse(priv)
		return t, nil
	}
```

It is important to keep track of the YubiKey's counter as well;
this is a 16-bit unsigned integer. The counter value in the token
should be checked against the last known counter value of the
YubiKey to prevent replay attacks.

## License

Package yubikey is licensed under the liberal ISC License.
