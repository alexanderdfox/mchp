[README.md](https://github.com/user-attachments/files/31420117/README.md)
# Secure MCHP Clock & Temporal State Machine

A cryptographically secure simulation combining an analog clock interface, circular orbit visualizations, temporal entropy injection, and binary-to-decimal stream translation. Available in both **Rust (Ratatui TUI)** and **HTML/JavaScript (Browser)** implementations.

---

## 🔒 Security Architecture

Both implementations replace weak pseudo-random number generators (PRNGs) with **Cryptographically Secure Pseudo-Random Number Generators (CSPRNG)** backed by operating system entropy and **SHA-256** hashing:

1. **True OS Kernel Entropy:** Pulls random bytes directly from the host operating system's hardware/kernel secure entropy pool (`getrandom` in Rust, `window.crypto.getRandomValues()` in JS).
2. **One-Way Cryptographic Hashing:** Combines the OS entropy with high-precision timestamps through **SHA-256**, ensuring state transitions are non-linear, unpredictable, and preimage-resistant against timing attacks.
3. **Temporal State Machine:** Evaluates secure metrics every second to determine halting states (`YES`/`NO`), dynamically mutating bits across a 360-bit ring orbit.

---

## 🚀 Implementations

### 1. Rust TUI (Ratatui)
Built with Rust, Crossterm, Ratatui, and `getrandom`.

#### Prerequisites
* [Rust toolchain](https://www.rust-lang.org/) installed.

#### Quick Start
1. Clone or navigate to the Rust project directory.
2. Ensure your `Cargo.toml` includes the required dependencies:
   ```toml
   [dependencies]
   chrono = "0.4"
   crossterm = "0.27"
   getrandom = "0.2"
   sha2 = "0.10"
   ratatui = "0.26"
   ```
3. Run the application:
   ```bash
   cargo run
   ```
4. Press **`Q`** or **`ESC`** to exit. The app automatically exports its secure stream to `active_stream.bin` on every tick.

---

### 2. Web / HTML Application
A single-file, zero-dependency browser visualization using the Web Crypto API.

#### Quick Start
1. Save the HTML code into a file named `index.html`.
2. Open `index.html` directly in any modern web browser (Chrome, Safari, Firefox, Edge).
3. The browser will instantly secure entropy, render the 360-bit circular orbit, display live clock hands, and stream real-time decimal conversions.

---

## 📂 Project Structure

```text
├── src/
│   └── main.rs         # Rust Ratatui TUI implementation
├── index.html          # Browser-based HTML/JS implementation
├── Cargo.toml          # Rust package configuration
├── active_stream.bin   # Exported binary stream artifact (ignored by git)
└── .gitignore          # Git exclusion rules
```

---

## 🛡️ License
This project is open source and available under the MIT License.
