# monitor_data.py

monitor_logs = []

def add_log(sender, receiver, plaintext, ciphertext, hash_value):
    monitor_logs.append({
        "sender": sender,
        "receiver": receiver,
        "plaintext": plaintext,
        "ciphertext": ciphertext,
        "hash": hash_value
    })

def get_logs():
    return monitor_logs
