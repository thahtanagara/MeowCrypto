     __    __  ___    ______   ____  _       __     _ 
   _/_/   /  |/  /   / ____/  / __ \| |     / /    | |
 _/_/    / /|_/ /   / __/    / / / /| | /| / /     / /
< <     / /  / /   / /___   / /_/ / | |/ |/ /     _>_>
/ /    /_/  /_/   /_____/   \____/  |__/|__/    _/_/  
\_\                                            /_/    

# MeowCrypto

**MeowCrypto** is a terminal-based tool for cryptographic operations, including encryption and decryption using AES, DES, RSA, and Vigenère ciphers. This project is designed for developers and security enthusiasts to experiment with various cryptographic algorithms.

## Features
- Encrypt and decrypt using AES (Advanced Encryption Standard).
- Encrypt and decrypt using DES (Data Encryption Standard).
- Encrypt and decrypt using RSA (Rivest-Shamir-Adleman).
- Encrypt and decrypt using the Vigenère cipher.
- User-friendly terminal interface.

---

## Installation

### Prerequisites
- Python 3.6 or higher
- `pip` (Python package manager)

### Steps
1. Clone this repository:
   ```bash
   git clone https://github.com/thahtanagara/MeowCrypto.git
   ```

2. Navigate to the project directory:
   ```bash
   cd MeowCrypto
   ```

3. Create and activate a virtual environment (optional but recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows, use venv\Scripts\activate
   ```

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

5. Make the script executable (Linux/Mac):
   ```bash
   chmod +x meow.py
   ```

---

## Usage

Run the tool from the terminal:

```bash
python3 meow.py
```

Or if made executable:

```bash
./meow.py
```

Follow the on-screen instructions to select an operation (encryption or decryption) and a cryptographic algorithm.

---

## Examples

### AES Encryption
Input:
```
Enter text to encrypt: Hello, World!
Enter key (16/24/32 bytes): mysecretkey12345
```
Output:
```
Encrypted text: b'\xf3\x1a\x9b\x0e...'
```

### RSA Decryption
Input:
```
Enter encrypted text: 0a3b...
Enter private key: -----BEGIN PRIVATE KEY----- ...
```
Output:
```
Decrypted text: Hello, World!
```

---

## Contribution

Contributions are welcome! Please submit a pull request or open an issue if you have ideas for improvements or additional features.

---

## License
This project is licensed under the MIT License. See the LICENSE file for more details.

---

## Acknowledgments
Special thanks to all contributors and the open-source community for their support.

---

Enjoy cryptographic experiments with **MeowCrypto**! 🐈

