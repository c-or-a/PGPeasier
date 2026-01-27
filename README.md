# PGPeasier by c.o.r.a.

SHA256: dad30b......509db2

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
