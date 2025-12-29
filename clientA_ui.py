# clientA_ui.py
import socket, threading, queue
import tkinter as tk
from tkinter import ttk, messagebox
import json, base64
import queue

from encrypt_view import EncryptView
from ecc_crypto import ECCSession

HOST = "127.0.0.1"
PORT = 9999

def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed")
        data += chunk
    return data

def recv_frame(sock: socket.socket) -> bytes:
    length = int.from_bytes(recv_exact(sock, 4), "big")
    return recv_exact(sock, length)

def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(len(payload).to_bytes(4, "big") + payload)

class ChatClientUI:
    def __init__(self, role="A"):
        self.role = role
        self.root = tk.Tk()
        self.root.title(f"Client {role} (ECC + AESGCM)")
        self.encrypt_log_queue = queue.Queue()

        self.session = ECCSession.create()
        self.sock = None
        self.inbox = queue.Queue()

        self._build_ui()
        self.root.after(100, self._drain_inbox)

        threading.Thread(
    target=lambda: EncryptView(self.encrypt_log_queue).run(),
    daemon=True
).start()

    def _build_ui(self):
        frm = ttk.Frame(self.root, padding=10)
        frm.grid(row=0, column=0, sticky="nsew")

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        frm.columnconfigure(0, weight=1)

        ttk.Label(frm, text=f"GIAO DIỆN {self.role}", font=("Segoe UI", 14, "bold")).grid(row=0, column=0, sticky="w")

        # Keys box
        keys_box = ttk.LabelFrame(frm, text="ECC Keys (PEM)")
        keys_box.grid(row=1, column=0, sticky="nsew", pady=8)
        keys_box.columnconfigure(0, weight=1)

        self.txt_pub = tk.Text(keys_box, height=6, wrap="none")
        self.txt_pub.grid(row=0, column=0, sticky="nsew")
        self.txt_pub.insert("1.0", self.session.get_public_key_bytes().decode("utf-8"))
        self.txt_pub.configure(state="disabled")

        # Chat view
        chat_box = ttk.LabelFrame(frm, text="Chat")
        chat_box.grid(row=2, column=0, sticky="nsew", pady=8)
        chat_box.columnconfigure(0, weight=1)

        self.txt_chat = tk.Text(chat_box, height=14, wrap="word")
        self.txt_chat.grid(row=0, column=0, sticky="nsew")
        self.txt_chat.configure(state="disabled")

        # Input
        input_box = ttk.Frame(frm)
        input_box.grid(row=3, column=0, sticky="ew")
        input_box.columnconfigure(0, weight=1)

        self.ent_msg = ttk.Entry(input_box)
        self.ent_msg.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.ent_msg.bind("<Return>", lambda e: self.send_message())

        ttk.Button(input_box, text="Gửi", command=self.send_message).grid(row=0, column=1)

        # Buttons
        btns = ttk.Frame(frm)
        btns.grid(row=4, column=0, sticky="ew", pady=8)
        ttk.Button(btns, text="Kết nối", command=self.connect).grid(row=0, column=0, padx=(0, 8))
        

    def log(self, s: str):
        self.txt_chat.configure(state="normal")
        self.txt_chat.insert("end", s + "\n")
        self.txt_chat.see("end")
        self.txt_chat.configure(state="disabled")

    def connect(self):
        if self.sock:
            messagebox.showinfo("Info", "Đã kết nối rồi.")
            return
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((HOST, PORT))

            # Send role
            send_frame(self.sock, self.role.encode("utf-8"))

            # Start receiver thread
            threading.Thread(target=self._recv_loop, daemon=True).start()

            # Send my public key to peer via server
            pub_b64 = base64.b64encode(self.session.get_public_key_bytes()).decode("utf-8")
            pkt = {"type": "PUBKEY", "from": self.role, "pub": pub_b64}
            send_frame(self.sock, json.dumps(pkt).encode("utf-8"))

            self.log("[*] Đã kết nối server và gửi Public Key.")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))
            self.sock = None

    def _recv_loop(self):
        try:
            while True:
                payload = recv_frame(self.sock)
                self.inbox.put(payload)
        except Exception as e:
            self.inbox.put(json.dumps({"type": "SYS", "msg": f"Mất kết nối: {e}"}).encode("utf-8"))

    def _drain_inbox(self):
        try:
            while True:
                payload = self.inbox.get_nowait()
                self._handle_payload(payload)
        except queue.Empty:
            pass
        self.root.after(100, self._drain_inbox)

    def _handle_payload(self, payload: bytes):
        try:
            pkt = json.loads(payload.decode("utf-8"))
        except:
            return

        t = pkt.get("type")
        if t == "PUBKEY":
            peer_pub = base64.b64decode(pkt["pub"])
            self.session.set_peer_public_key_bytes(peer_pub)
            self.log("[+] Nhận Public Key của peer -> đã sinh AES key (ECDH + HKDF).")

        elif t == "MSG":
            nonce = base64.b64decode(pkt["nonce"])
            ct = base64.b64decode(pkt["ct"])
            try:
                pt = self.session.decrypt(nonce, ct)
                
                self.log(f"Peer: {pt}")
            except Exception as e:
                self.log(f"[!] Giải mã lỗi: {e}")
                self.encrypt_log_queue.put(
                    f"[RECV - {self.role}]\n"
                    f"Ciphertext: {ct.hex()}\n"
                    f"Nonce     : {nonce.hex()}\n"
                    f"Plaintext : {pt}\n"
                    f"AES key   : {self.session.aes_key.hex()}"
)

        elif t == "SYS":
            self.log("[SYS] " + pkt.get("msg", ""))

    def send_message(self):
        if not self.sock:
            messagebox.showwarning("Chưa kết nối", "Nhấn Kết nối trước.")
            return

        msg = self.ent_msg.get().strip()
        if not msg:
            return

        if self.session.aes_key is None:
            messagebox.showwarning("Chưa có khóa", "Chưa nhận Public Key của B nên chưa mã hóa được.")
            return

        nonce, ct = self.session.encrypt(msg)
        self.encrypt_log_queue.put(
            f"[SEND - {self.role}]\n"
            f"Plaintext : {msg}\n"
            f"Nonce     : {nonce.hex()}\n"
            f"Ciphertext: {ct.hex()}\n"
            f"AES key   : {self.session.aes_key.hex()}"
)
        pkt = {
            "type": "MSG",
            "from": self.role,
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ct": base64.b64encode(ct).decode("utf-8"),
        }
        send_frame(self.sock, json.dumps(pkt).encode("utf-8"))
        self.log("Me: " + msg)
        self.ent_msg.delete(0, "end")

    def open_encrypt_ui(self):
        # mở encrypt_ui.py như 1 cửa sổ riêng (tạm dùng Toplevel hiển thị nhanh)
        top = tk.Toplevel(self.root)
        top.title("Giao diện Mã hóa (View)")

        frm = ttk.Frame(top, padding=10)
        frm.grid(row=0, column=0, sticky="nsew")
        top.columnconfigure(0, weight=1)
        top.rowconfigure(0, weight=1)
        frm.columnconfigure(0, weight=1)

        ttk.Label(frm, text="GIAO DIỆN HIỂN THỊ MÃ HÓA", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky="w")

        ttk.Label(frm, text="AES key (hex) - sinh ra từ ECDH + HKDF:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        txt_key = ttk.Entry(frm)
        txt_key.grid(row=2, column=0, sticky="ew")
        txt_key.insert(0, self.session.aes_key.hex() if self.session.aes_key else "(chưa có)")

        ttk.Label(frm, text="Ghi chú: Tin nhắn chat sẽ được AES-GCM mã hóa.\nECC chỉ dùng để tạo shared secret.", foreground="gray").grid(row=3, column=0, sticky="w", pady=8)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    ChatClientUI("A").run()
