import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import tkinter.scrolledtext as scrolledtext
import hashlib
import json
import threading
from datetime import datetime
import random
import string

class Wallet:
    def __init__(self,root):
        self.root = root
        self.root.title("PQC Wallet")
        self.root.geometry("800x700")
        self.root.configure(bg="#1e1e1e")
        self.wallet = None
        self.transactions = []
        self.setup_ui()
        self.log("Wallet initialized")

    def setup_ui(self):
        title = tk.Label(
            self.root,
            text=("Secure Wallet"),
            font = ("Arial", 18, "bold"),
            fg = "#00ff88"
            
        )
       
        
        title.pack(pady=10)

        notebook = ttk.Notebook(self.root)
        self.wallet_tab = ttk.Frame(notebook)
        self.tx_tab = ttk.Frame(notebook)
        self.log_tab = ttk.Frame(notebook)
        notebook.add(self.wallet_tab, text="Wallet")
        notebook.add(self.tx_tab, text="Transaction")
        notebook.add(self.log_tab, text="logs")
        self.setup_wallet_tab()
        self.setup_tx_tab()
        self.setup_log_tab()

    def setup_wallet_tab(self):
        frame = tk.Frame(self.wallet_tab, bg= "#1e1e1e")
        frame.pack(fill="x", padx=10, pady=10)
        
        tk.Label(frame,text = "Wallet Address", fg="white", bg ="#1e1e1e").pack(anchor = "w")

        self.address_var = tk.StringVar()
        tk.Entry(
            frame,
            textvariable=self.address_var,
            state = "readonly",
            font = ("Courier",10),
            bg="#2d2d2d",
            fg = "#00ff88"
        ).pack(fill="x", pady=5)

        btns = tk.Frame(self.wallet_tab, bg="#1e1e1e")
        btns.pack(pady=20)

        tk.Button(btns, text="Generate Wallet",
                  command=self.generate_wallet_thread,
                  width=18,height=2).pack(side="left",padx=5)
        tk.Button(btns, text="Save Wallet",
                  command=self.save_wallet,
                  width=18,height=2).pack(side="left",padx=5)
        tk.Button(btns, text="Load Wallet",
                  command=self.load_wallet,
                  width=18,height=2).pack(side="left",padx=5)
    

    def setup_tx_tab(self):
        frame = tk.LabelFrame(self.tx_tab, text="Create Transaction")
        frame.pack(fill="x", padx=10, pady=10)

        tk.Label(frame, text="To Address").grid(row=0, column=0, padx=5, pady=5)
        self.to_entry = tk.Entry(frame, width=50)
        self.to_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(frame, text="Amount").grid(row=1, column=0, padx=5, pady=5)
        self.amount_entry = tk.Entry(frame)
        self.amount_entry.grid(row=1, column=1, sticky="w", padx=5, pady=5)

        tk.Button(frame, text="Create TX",
                  command=self.create_tx_thread).grid(row=2, column=1, pady=10)

        self.tx_list = tk.Listbox(self.tx_tab, font=("Courier", 9))
        self.tx_list.pack(fill="both", expand=True, padx=10, pady=10)
    def setup_log_tab(self):
        self.log_box = scrolledtext.ScrolledText(
            self.log_tab,
            font=("Courier", 9),
            bg="#1a1a1a",
            fg="#00ff88"
        )
        self.log_box.pack(fill="both", expand=True, padx=10, pady=10)

    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_box.insert(tk.END, f"[{ts}] {msg}\n")
        self.log_box.see(tk.END)
    
    def generate_wallet_thread(self):
        threading.Thread(target=self.generate_wallet, daemon=True).start()

    def generate_wallet(self):
        self.log(" Generating wallet...")
        random_data = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        address = hashlib.sha256(random_data.encode()).hexdigest()[:40]

        self.wallet = {
            "address": address,
            "created": datetime.now().isoformat()
        }

        self.address_var.set(address)
        self.log("✅ Wallet generated")

    def save_wallet(self):
        if not self.wallet:
            messagebox.showerror("Error", "No wallet to save")
            return

        file = filedialog.asksaveasfilename(defaultextension=".json")
        if file:
            with open(file, "w") as f:
                json.dump(self.wallet, f, indent=4)
            self.log(" Wallet saved")

    def load_wallet(self):
        file = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if file:
            with open(file, "r") as f:
                self.wallet = json.load(f)
            self.address_var.set(self.wallet["address"])
            self.log("Wallet loaded")
    def create_tx_thread(self):
        threading.Thread(target=self.create_tx, daemon=True).start()

    def create_tx(self):
        if not self.wallet:
            messagebox.showerror("Error", "Create wallet first")
            return

        try:
            to_addr = self.to_entry.get()
            amount = float(self.amount_entry.get())

            tx_data = f"{self.wallet['address']}{to_addr}{amount}{datetime.now()}"
            tx_hash = hashlib.sha256(tx_data.encode()).hexdigest()

            tx = {
                "from": self.wallet["address"],
                "to": to_addr,
                "amount": amount,
                "hash": tx_hash
            }

            self.transactions.append(tx)
            self.tx_list.insert(0, f"{tx_hash[:16]} → {to_addr[:16]} ({amount})")
            self.log(" Transaction created")

            self.to_entry.delete(0, tk.END)
            self.amount_entry.delete(0, tk.END)

        except ValueError:
            self.log(" Invalid amount")

def main():
    root = tk.Tk()
    Wallet(root)
    root.mainloop()

if __name__ == "__main__":
    main()

