# PGPeasier by c.o.r.a.
A Python based PGP tool with keyring encryption.

SHA256: bb7ee4......8b8baf

## v3.0.5
* Removed janky anti debug/vm/keylog slop code.
* Added Themida 3.2.2.22 protected binary to release, allowing users to curate their security.

## v3.0.3

* Constant-time comparisons for all sensitive operations to prevent timing attacks.
* Real-time, not just run-time, anti debugger/keylogger/virtual-machine.
* Updated hash and salt creation for file encryption.
* Now using AES GCM for file encryption.

## v3.0.2

* Files no longer assymetrically encrypted with the public RSA key, which is vulnerable to Shor's algorithm.
* Now uses a combination of the password hash and a hash of the private key. Ensuring your files are quantum resistant.

## 2026 Security Update

* Same intuitive GUI
* Requires admin permissions
* Window title bar uses system theme
* Now uses AES-256 GCM instead of AES-128 CBC
* Passwords now salted with 1.2M PBKDF2 iterations
* Keys remain encrypted when unlocked
* Password stored securely in memory and zeroed after use
* Blocks execution if unsigned drivers detected
* Blocks execution if analysis tools detected (x64dbg, Ghidra, etc.)
* Warns on suspicious processes/drivers (user can continue)

---

**License:** Original code © 2026 c.o.r.a. (GPLv3)</br>
**Note:** Users responsible for key security and backups.

<img width="350" height="175" alt="v3" src="https://github.com/user-attachments/assets/3d8c1900-7fb6-4de4-8dcf-2083111886ea" />
