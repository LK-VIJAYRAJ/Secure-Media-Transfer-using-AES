import os
import hashlib
from tkinter import filedialog, messagebox, Tk, Label, Entry, Button, StringVar
from Crypto.Cipher import AES

ENCRYPTION_HEADER = b'SECURE_AES_ENCRYPTED'

class EncryptionTool:
    def __init__(self, user_file, user_key):
        self.user_file = user_file
        self.input_file_size = os.path.getsize(self.user_file)
        self.chunk_size = 1024
        self.total_chunks = (self.input_file_size // self.chunk_size) + 1
        self.user_key = bytes(user_key, "utf-8")
        self.output_file = self.user_file + ".encr"
        self.hash_type = "sha256"
        self.hashed_key_salt = {}
        self.hash_key_salt()

    def read_in_chunks(self, file_object, chunk_size=1024):
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def encrypt(self):
        cipher = AES.new(self.hashed_key_salt["key"], AES.MODE_CFB, self.hashed_key_salt["salt"])
        self.abort()
        with open(self.user_file, "rb") as infile, open(self.output_file, "xb") as outfile:
            outfile.write(ENCRYPTION_HEADER)  # Write header
            for chunk in self.read_in_chunks(infile):
                outfile.write(cipher.encrypt(chunk))
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

class EncryptorGUI:
    def __init__(self, root):
        self.root = root
        self.file_path = StringVar()
        self.secret_key = StringVar()

        root.title("File Encryptor")
        root.geometry("400x220")

        Label(root, text="Select File to Encrypt:").pack(pady=5)
        Entry(root, textvariable=self.file_path, width=50).pack()
        Button(root, text="Browse", command=self.select_file).pack(pady=5)

        Label(root, text="Enter Secret Key:").pack(pady=5)
        Entry(root, textvariable=self.secret_key, show="*", width=50).pack()

        Button(root, text="Encrypt", command=self.encrypt_file, bg="green", fg="white").pack(pady=10)

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path.set(file_path)

    def encrypt_file(self):
        if not self.file_path.get() or not self.secret_key.get():
            messagebox.showwarning("Input Error", "Please provide both file and key.")
            return
        try:
            tool = EncryptionTool(self.file_path.get(), self.secret_key.get())
            tool.encrypt()
            messagebox.showinfo("Success", f"File encrypted successfully as:\n{tool.output_file}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = Tk()
    app = EncryptorGUI(root)
    root.mainloop()
