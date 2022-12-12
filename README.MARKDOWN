# otpdec

This utility will decode a TOTP (Time-based One-Time Password) secret into a six digit authenticator code.

The motivation was a need for something that wasn't quite a password manager, but could still generate OTP codes. This can be used in combination with something like OpenPGP to script OTP generation, including putting the output on the clipboard with something like `pbcopy` or `xclip`:

```sh
gpg --decrypt ~/.otp/MyEmailAccount.gpg | otpdec | pbcopy
```

Input should be _only_ the secret, not the full `totp://` URL.


### Limitations

Currently, only SHA1 is supported.
Only 6 digit codes are generated. 
Only 30-second time steps are supported.
