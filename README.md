# gloom

A simple console TOTP app.

cargo build --release to make executable.
Executable uses its directory as working, creating .vault files. No sanity checks are done with vault names, so don't do fun stuff.
Each vault is protected by its password, using Cocoon crate.

./gloom add vaultname : will create a vault with this name.

./gloom otp vaultname : will output current OTP codes for this vault. Press q to exit.
