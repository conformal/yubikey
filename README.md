yubikey
=======

Package yubikey implements the [Yubico](http://www.yubico.com) [yubikey](http://www.yubico.com/products/yubikey-hardware/) API.

## Example

The package needs to know the secret key of the Yubikey token; this
may be stored as a string. For example, the secret key could be
loaded from a file with:

```
import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
)

func LoadSecretKey(filename string) (priv *Key, err error) {
	in, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}

	in, err = bytes.TrimSpace(in)
	if err != nil {
		return
	}
	
	keyBytes := make([]byte, len(in) / 2)
	err = hex.Decode(keyBytes, in)
	if err != nil {
		return
	}

	priv = yubikey.NewKey(keyBytes)
	return
}
```

Then, you can pass the OTP string directly from the Yubikey to
`ParseOtpString`:

```
	func GetToken(otpString string, priv *Key) (t *Token, err error) {
		pub, otp, err := yubikey.ParseOtpString(otpString)
		if err != nil {
			return
		}

	        keyBytes, _ := hex.DecodeString(secretKey)
		t, err = otp.Parse(priv)
		return
	}
```

It is important to keep track of the Yubikey's counter as well;
this is a 16-bit unsigned integer. The counter value in the token
should be checked against the last known counter value of the
Yubikey to prevent replay attacks.

## License

Package yubikey is licensed under the liberal ISC License.
