# server_relay.py
import socket
import threading
import json

HOST = "127.0.0.1"
PORT = 9999

clients = {}        # role -> socket
public_keys = {}    # role -> payload public key (bytes)
lock = threading.Lock()


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


def handle_client(conn: socket.socket, addr):
    role = None
    try:
        # ===== Nhận role =====
        role = recv_frame(conn).decode("utf-8").strip()
        if role not in ("A", "B"):
            conn.close()
            return

        with lock:
            clients[role] = conn

        print(f"[+] {role} connected from {addr}")

        # ===== Nếu peer đã có public key → gửi lại ngay =====
        other = "B" if role == "A" else "A"
        with lock:
            if other in public_keys:
                send_frame(conn, public_keys[other])

        # ===== Relay loop =====
        while True:
            payload = recv_frame(conn)

            try:
                pkt = json.loads(payload.decode("utf-8"))
            except:
                continue

            pkt_type = pkt.get("type")

            # ===== Nếu là PUBLIC KEY =====
            if pkt_type == "PUBKEY":
                with lock:
                    public_keys[role] = payload

                print(f"[KEY] Received public key from {role}")

                # gửi public key này cho peer nếu peer tồn tại
                with lock:
                    other_sock = clients.get(other)

                if other_sock:
                    send_frame(other_sock, payload)

            # ===== Nếu là MESSAGE =====
            else:
                with lock:
                    other_sock = clients.get(other)

                if other_sock:
                    send_frame(other_sock, payload)

    except Exception as e:
        print(f"[-] client error {addr}: {e}")

    finally:
        with lock:
            if role in clients:
                del clients[role]
            if role in public_keys:
                del public_keys[role]

        try:
            conn.close()
        except:
            pass

        print(f"[*] disconnected {addr}")


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)
    print(f"Server listening on {HOST}:{PORT}")

    while True:
        conn, addr = srv.accept()
        threading.Thread(
            target=handle_client,
            args=(conn, addr),
            daemon=True
        ).start()


if __name__ == "__main__":
    main()
