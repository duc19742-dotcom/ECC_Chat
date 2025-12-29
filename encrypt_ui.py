# encrypt_ui.py
import tkinter as tk
from tkinter import ttk, messagebox
import base64

from ecc_crypto import ECCSession, bytes_to_pubkey

class EncryptUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Encrypt UI - ECC(ECDH) + AESGCM")

        self.session = ECCSession.create()

        self._build()

    def _build(self):
        frm = ttk.Frame(self.root, padding=10)
        frm.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        frm.columnconfigure(0, weight=1)

        ttk.Label(frm, text="GIAO DIỆN HIỂN THỊ MÃ HÓA", font=("Segoe UI", 14, "bold")).grid(row=0, column=0, sticky="w")

        # my pub
        box1 = ttk.LabelFrame(frm, text="Public Key của tôi (PEM)")
        box1.grid(row=1, column=0, sticky="nsew", pady=8)
        box1.columnconfigure(0, weight=1)

        self.txt_my = tk.Text(box1, height=6)
        self.txt_my.grid(row=0, column=0, sticky="nsew")
        self.txt_my.insert("1.0", self.session.get_public_key_bytes().decode("utf-8"))

        # peer pub
        box2 = ttk.LabelFrame(frm, text="Dán Public Key của peer (PEM)")
        box2.grid(row=2, column=0, sticky="nsew", pady=8)
        box2.columnconfigure(0, weight=1)

        self.txt_peer = tk.Text(box2, height=6)
        self.txt_peer.grid(row=0, column=0, sticky="nsew")

        ttk.Button(frm, text="Derive AES key (ECDH + HKDF)", command=self.derive).grid(row=3, column=0, sticky="w", pady=6)

        ttk.Label(frm, text="AES key (hex):").grid(row=4, column=0, sticky="w")
        self.ent_key = ttk.Entry(frm)
        self.ent_key.grid(row=5, column=0, sticky="ew", pady=(0, 8))

        # plaintext/cipher
        box3 = ttk.LabelFrame(frm, text="Thử mã hóa")
        box3.grid(row=6, column=0, sticky="nsew", pady=8)
        box3.columnconfigure(0, weight=1)

        ttk.Label(box3, text="Plaintext:").grid(row=0, column=0, sticky="w")
        self.ent_plain = ttk.Entry(box3)
        self.ent_plain.grid(row=1, column=0, sticky="ew", pady=(0, 6))

        ttk.Button(box3, text="Encrypt", command=self.do_encrypt).grid(row=2, column=0, sticky="w")

        ttk.Label(box3, text="Nonce (base64):").grid(row=3, column=0, sticky="w", pady=(8, 0))
        self.ent_nonce = ttk.Entry(box3)
        self.ent_nonce.grid(row=4, column=0, sticky="ew")

        ttk.Label(box3, text="Ciphertext (base64):").grid(row=5, column=0, sticky="w", pady=(8, 0))
        self.ent_ct = ttk.Entry(box3)
        self.ent_ct.grid(row=6, column=0, sticky="ew")

        ttk.Button(box3, text="Decrypt", command=self.do_decrypt).grid(row=7, column=0, sticky="w", pady=6)

        ttk.Label(box3, text="Kết quả giải mã:").grid(row=8, column=0, sticky="w")
        self.ent_out = ttk.Entry(box3)
        self.ent_out.grid(row=9, column=0, sticky="ew")

    def derive(self):
        try:
            peer_pem = self.txt_peer.get("1.0", "end").encode("utf-8")
            # validate
            _ = bytes_to_pubkey(peer_pem)
            self.session.set_peer_public_key_bytes(peer_pem)
            self.ent_key.delete(0, "end")
            self.ent_key.insert(0, self.session.aes_key.hex())
            messagebox.showinfo("OK", "Đã derive AES key.")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    def do_encrypt(self):
        try:
            pt = self.ent_plain.get()
            nonce, ct = self.session.encrypt(pt)
            self.ent_nonce.delete(0, "end")
            self.ent_ct.delete(0, "end")
            self.ent_nonce.insert(0, base64.b64encode(nonce).decode("utf-8"))
            self.ent_ct.insert(0, base64.b64encode(ct).decode("utf-8"))
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    def do_decrypt(self):
        try:
            nonce = base64.b64decode(self.ent_nonce.get().strip())
            ct = base64.b64decode(self.ent_ct.get().strip())
            pt = self.session.decrypt(nonce, ct)
            self.ent_out.delete(0, "end")
            self.ent_out.insert(0, pt)
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    EncryptUI().run()
