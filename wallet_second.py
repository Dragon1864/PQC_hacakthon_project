import json
import time
import hashlib
from datetime import datetime
import oqs

# =================================================
# FPGA HASH (SIMULATED – UART READY)
# =================================================
def simulated_fpga_hash(tx_dict):
    """
    Simulates SHA-256 hashing done on FPGA.
    Replace this with UART send/receive later.
    """
    canonical = json.dumps(tx_dict, sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


# =================================================
# WALLET (OQS DILITHIUM)
# =================================================
class Wallet:
    def __init__(self):
        self.public_key = None
        self.private_key = None
        self.address = None

    def create_wallet(self):
        """
        Generate Dilithium3 keypair using OQS
        """
        with oqs.Signature("Dilithium3") as signer:
            self.public_key = signer.generate_keypair()
            self.private_key = signer.export_secret_key()

        # Wallet address = hash of public key
        self.address = hashlib.sha256(self.public_key).hexdigest()[:40]

    def save(self, filename):
        data = {
            "public_key": self.public_key.hex(),
            "private_key": self.private_key.hex(),
            "address": self.address
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)

    def load(self, filename):
        with open(filename, "r") as f:
            data = json.load(f)

        self.public_key = bytes.fromhex(data["public_key"])
        self.private_key = bytes.fromhex(data["private_key"])
        self.address = data["address"]


# =================================================
# TRANSACTION
# =================================================
class Transaction:
    def __init__(self, sender, receiver, amount):
        self.sender = sender
        self.receiver = receiver
        self.amount = int(amount * 100)   # fixed-point
        self.timestamp = datetime.now().isoformat()
        self.hash = None
        self.signature = None

    def to_dict(self):
        return {
            "from": self.sender,
            "to": self.receiver,
            "amount": self.amount,
            "timestamp": self.timestamp
        }

    def attach_hash(self, h):
        self.hash = h

    def attach_signature(self, sig):
        self.signature = sig.hex()

    def full(self):
        return {
            **self.to_dict(),
            "hash": self.hash,
            "signature": self.signature
        }


# =================================================
# SIGN & VERIFY (OQS)
# =================================================
def sign_transaction(tx_hash_hex, private_key):
    """
    Sign transaction hash using Dilithium3
    """
    with oqs.Signature("Dilithium3", secret_key=private_key) as signer:
        return signer.sign(bytes.fromhex(tx_hash_hex))


def verify_transaction(tx_hash_hex, signature_hex, public_key):
    """
    Verify Dilithium3 signature
    """
    try:
        with oqs.Signature("Dilithium3") as verifier:
            verifier.verify(
                bytes.fromhex(tx_hash_hex),
                bytes.fromhex(signature_hex),
                public_key
            )
        return True
    except Exception:
        return False


# =================================================
# MAIN
# =================================================
def main():
    print("\n=== Post-Quantum Wallet (OQS Dilithium3) ===\n")

    wallet = Wallet()

    print("1. Create new wallet")
    print("2. Load existing wallet")
    choice = input("Select option (1/2): ").strip()

    if choice == "1":
        wallet.create_wallet()
        print("\nWallet created!")
        print("Address:", wallet.address)

        if input("Save wallet? (y/n): ").lower() == "y":
            fname = input("Filename (e.g. wallet.json): ")
            wallet.save(fname)
            print("Wallet saved.")

    elif choice == "2":
        fname = input("Wallet filename: ")
        wallet.load(fname)
        print("\nWallet loaded!")
        print("Address:", wallet.address)

    else:
        print("Invalid option.")
        return

    # ---------------------------------------------
    # TRANSACTION FLOW
    # ---------------------------------------------
    print("\n--- Create Transaction ---")
    receiver = input("Receiver address: ")
    amount = float(input("Amount: "))

    tx = Transaction(wallet.address, receiver, amount)

    print("\nSending transaction to FPGA for hashing...")
    time.sleep(1)

    tx_hash = simulated_fpga_hash(tx.to_dict())
    tx.attach_hash(tx_hash)

    print("Hash received:", tx_hash)

    print("\nSigning transaction with Dilithium3...")
    signature = sign_transaction(tx.hash, wallet.private_key)
    tx.attach_signature(signature)

    valid = verify_transaction(
        tx.hash,
        tx.signature,
        wallet.public_key
    )

    print("\nVerification:", "VALID ✅" if valid else "INVALID ❌")

    print("\nFinal Transaction:")
    print(json.dumps(tx.full(), indent=4))


if __name__ == "__main__":
    main()
