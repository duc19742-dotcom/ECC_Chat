# encrypt_view.py
import tkinter as tk
from tkinter import ttk
import queue
import threading

class EncryptView:
    def __init__(self, log_queue: queue.Queue):
        self.q = log_queue
        self.root = tk.Tk()
        self.root.title("GIAO DIỆN HIỂN THỊ MÃ HÓA ")

        frm = ttk.Frame(self.root, padding=10)
        frm.grid(sticky="nsew")

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        frm.columnconfigure(0, weight=1)

        ttk.Label(
            frm,
            text="GIAO DIỆN HIỂN THỊ MÃ HÓA ",
            font=("Segoe UI", 13, "bold")
        ).grid(row=0, column=0, sticky="w")

        self.txt = tk.Text(frm, height=20, wrap="word")
        self.txt.grid(row=1, column=0, sticky="nsew", pady=8)
        self.txt.configure(state="disabled")

        self.root.after(100, self.poll)

    def poll(self):
        try:
            while True:
                log = self.q.get_nowait()
                self.append(log)
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def append(self, text: str):
        self.txt.configure(state="normal")
        self.txt.insert("end", text + "\n\n")
        self.txt.see("end")
        self.txt.configure(state="disabled")

    def run(self):
        self.root.mainloop()
