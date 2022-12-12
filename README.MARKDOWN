# otpdec

This utility will decode a TOTP (Time-based One-Time Password) secret into a six digit authenticator code.

The motivation was a need for something that wasn't quite a password manager, but could still generate OTP codes. This can be used in combination with something like OpenPGP to script OTP generation, including putting the output on the clipboard with something like `pbcopy` or `xclip`:

```sh
gpg --decrypt ~/.otp/MyEmailAccount.gpg | otpdec | pbcopy
```
