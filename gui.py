import tkinter as tk
from tkinter import ttk

class ChatGUI:
    def __init__(self, on_start, on_send):
        self.root = tk.Tk()
        self.root.title("ECC Chat")

        self.on_send = on_send

        # ===== CHỌN USER =====
        self.user = tk.StringVar(value="A")

        frame_top = ttk.Frame(self.root)
        frame_top.pack(pady=5)

        ttk.Label(frame_top, text="Chọn người dùng:").pack(side="left", padx=5)
        ttk.Radiobutton(frame_top, text="User A", variable=self.user, value="A").pack(side="left")
        ttk.Radiobutton(frame_top, text="User B", variable=self.user, value="B").pack(side="left")

        ttk.Button(
            frame_top,
            text="Bắt đầu",
            command=lambda: on_start(self.user.get())
        ).pack(side="left", padx=10)

        # ===== CHAT =====
        self.text_area = tk.Text(self.root, height=15, state="disabled")
        self.text_area.pack(padx=10, pady=5)

        self.entry = ttk.Entry(self.root, width=50)
        self.entry.pack(padx=10, pady=5)

        ttk.Button(
            self.root,
            text="Gửi",
            command=self.send
        ).pack(pady=5)

    def send(self):
        msg = self.entry.get()
        if msg:
            self.on_send(msg)
            self.entry.delete(0, tk.END)

    def display(self, msg):
        self.text_area.config(state="normal")
        self.text_area.insert(tk.END, msg + "\n")
        self.text_area.config(state="disabled")

    def run(self):
        self.root.mainloop()
