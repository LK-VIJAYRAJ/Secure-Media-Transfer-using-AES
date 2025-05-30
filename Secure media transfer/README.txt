README.txt

AES File Encryptor & Decryptor GUI Tools

This project provides two Python-based GUI tools to encrypt and decrypt files using AES (Advanced Encryption Standard) encryption with a user-provided key.

---

🔐 Tools Included:

1. file_encryptor.py
   - Encrypts any file using a password-derived AES key.
   - Output file will have a .encr extension.

2. file_decryptor.py
   - Decrypts files previously encrypted with the above tool.
   - Output file will have a .decr extension.

---

⚙️ Requirements:

- Python 3.x
- Required Libraries:
  - pycryptodome (Install with `pip install pycryptodome`)
  - tkinter (Usually included with Python)

---

🚀 How to Use:

1. Encryption
- Run file_encryptor.py:
  python file_encryptor.py

- In the GUI:
  - Click Browse to select a file to encrypt.
  - Enter a Secret Key (minimum recommended: 16 characters).
  - Click Encrypt.
- Encrypted file is saved as: filename.ext.encr

2. Decryption
- Run file_decryptor.py:
  python file_decryptor.py

- In the GUI:
  - Click Browse to select a .encr file.
  - Enter the same Secret Key used during encryption.
  - Click Decrypt.
- Decrypted file is saved as: filename.ext.encr.decr

---

🔒 Security Notes:
- AES encryption is performed in CFB mode using a salted key derived from SHA-256.
- A header (SECURE_AES_ENCRYPTED) is added to encrypted files to verify authenticity.
- Files are processed in chunks (1024 bytes) to support large file sizes.

---

🧪 Example:
- Encrypting report.pdf with key MySecretKey123 → report.pdf.encr
- Decrypting report.pdf.encr with the same key → report.pdf.encr.decr

---

📁 Output File Cleanup
- If the output file already exists, it will be deleted and re-created during encryption/decryption to prevent corruption.

---

📝 Disclaimer
This tool is for educational/demo purposes. It should not be used as-is for production or high-security applications without thorough review and enhancement.
