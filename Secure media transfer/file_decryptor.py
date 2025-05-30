import os
import hashlib
from tkinter import filedialog, messagebox, Tk, Label, Entry, Button, StringVar
from Crypto.Cipher import AES

ENCRYPTION_HEADER = b'SECURE_AES_ENCRYPTED'

class DecryptionTool:
    def __init__(self, encrypted_file, user_key):
        self.encrypted_file = encrypted_file
        self.chunk_size = 1024
        self.user_key = bytes(user_key, "utf-8")
        self.output_file = encrypted_file + ".decr"
        self.hash_type = "sha256"
        self.hashed_key_salt = {}
        self.hash_key_salt()

    def read_in_chunks(self, file_object, chunk_size=1024):
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def decrypt(self):
        cipher = AES.new(self.hashed_key_salt["key"], AES.MODE_CFB, self.hashed_key_salt["salt"])
        self.abort()
        with open(self.encrypted_file, "rb") as infile:
            header = infile.read(len(ENCRYPTION_HEADER))
            if header != ENCRYPTION_HEADER:
                raise ValueError("Invalid key or file is not properly encrypted.")
            with open(self.output_file, "xb") as outfile:
                for chunk in self.read_in_chunks(infile):
                    outfile.write(cipher.decrypt(chunk))
        del cipher

    def abort(self):
        if os.path.isfile(self.output_file):
            os.remove(self.output_file)

    def hash_key_salt(self):
        key_hasher = hashlib.new(self.hash_type)
        key_hasher.update(self.user_key)
        self.hashed_key_salt["key"] = bytes.fromhex(key_hasher.hexdigest())[:32]
        salt_hasher = hashlib.new(self.hash_type)
        salt_hasher.update(self.user_key[::-1])
        self.hashed_key_salt["salt"] = bytes.fromhex(salt_hasher.hexdigest())[:16]

class DecryptorGUI:
    def __init__(self, root):
        self.root = root
        self.file_path = StringVar()
        self.secret_key = StringVar()

        root.title("File Decryptor")
        root.geometry("400x220")

        Label(root, text="Select File to Decrypt:").pack(pady=5)
        Entry(root, textvariable=self.file_path, width=50).pack()
        Button(root, text="Browse", command=self.select_file).pack(pady=5)

        Label(root, text="Enter Secret Key:").pack(pady=5)
        Entry(root, textvariable=self.secret_key, show="*", width=50).pack()

        Button(root, text="Decrypt", command=self.decrypt_file, bg="blue", fg="white").pack(pady=10)

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path.set(file_path)

    def decrypt_file(self):
        if not self.file_path.get() or not self.secret_key.get():
            messagebox.showwarning("Input Error", "Please provide both file and key.")
            return
        try:
            tool = DecryptionTool(self.file_path.get(), self.secret_key.get())
            tool.decrypt()
            messagebox.showinfo("Success", f"File decrypted successfully as:\n{tool.output_file}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = Tk()
    app = DecryptorGUI(root)
    root.mainloop()
