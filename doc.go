/*
   Package yubikey implements the Yubico Yubikey OTP API, using 6-byte
   public identities and 16-byte secret keys.

   Given a Yubikey private key and the generated OTP, this package
   provides for validation of OTP tokens.

   A key is set up by passing the bytes into the NewKey function;
   Yubikey secret keys are 32-bytes and hex-encoded. For example,
   the Yubikey personalisation tool will provide a key like
   "99cbcef30228f2539aa20358c46c0ad2".

   A typical OTP token looks something like
   "ccccccbtirngifjtulftrrijbkuuhtcgvhfdehighcdh"; in this case,
   "ccccccbtirng" is the 12-byte modhex-encoded public identity,
   while the rest of the string contains the actual token. The token
   can be parsed with the NewOtp or ParseOtpString functions, which
   converts a string containing the token to a valid OTP structure.
   This OTP can be validated and turned into a token using the Parse
   method. The NewOTP requires a string containing only the 32-byte
   token, while ParseOTPString will take the string directly from
   the Yubikey and returns a UID and OTP.

   See examples/login/login.go for an example login authentication
   flow.
*/
package yubikey
