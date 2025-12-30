from flask import Flask, render_template, request, redirect, session
from flask_socketio import SocketIO, join_room, emit
from datetime import datetime
import hashlib
from ecc_crypto import ECCRoomKey
import json, os
LOG_FILE = "chat_logs.json"
# ==============================
#        FLASK CONFIG
# ==============================
cipher_logs = []
app = Flask(__name__)
app.config["SECRET_KEY"] = "super_secret_key"
socketio = SocketIO(app, cors_allowed_origins="*")

# ==============================
#        USERS (DEMO)
# ==============================
USERS = {
    "alice": {"password": "123456@", "name": "Alice"},
    "bob": {"password": "123456@", "name": "Bob"},
    "charlie": {"password": "123456@", "name": "Charlie"},
}

# ==============================
#        CHAT STORAGE (RAM)
# ==============================
chat_history = {}   # room -> list messages
pair_keys = {}      # room -> ECC key


def get_room(u1, u2):
    return "_".join(sorted([u1, u2]))


# ==============================
#            LOGIN
# ==============================
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u in USERS and USERS[u]["password"] == p:
            session["username"] = u
            session["name"] = USERS[u]["name"]
            return redirect("/friends")

    return render_template("login.html")


# ==============================
#          FRIEND LIST
# ==============================
@app.route("/friends")
def friends():
    if "username" not in session:
        return redirect("/")

    me = session["username"]
    friends = [
        {"username": u, "name": USERS[u]["name"]}
        for u in USERS if u != me
    ]

    return render_template(
        "friends.html",
        current_user=session["name"],
        friends=friends
    )


# ==============================
#            CHAT
# ==============================
@app.route("/chat/<target>")
def chat(target):
    if "username" not in session:
        return redirect("/")

    if target not in USERS:
        return redirect("/friends")

    me = session["username"]
    room = get_room(me, target)

    if room not in pair_keys:
        pair_keys[room] = ECCRoomKey()

    if room not in chat_history:
        chat_history[room] = []

    #  DÙNG FILE chat_user.html (CÓ NÚT QUAY LẠI)
    return render_template(
        "chat_user.html",
        me_username=me,
        target_username=target,
        room=room,
        history=chat_history[room]
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ==============================
#          SOCKET EVENTS
# ==============================
@socketio.on("join_private")
def join_private(data):
    room = data.get("room")
    if room:
        join_room(room)


@socketio.on("send_private")
def send_private(data):
    room = data["room"]
    sender = data["sender"]
    receiver = data["receiver"]
    msg = data["msg"]

    if room not in pair_keys:
        pair_keys[room] = ECCRoomKey()
    if room not in chat_history:
        chat_history[room] = []

    ecc = pair_keys[room]
    cipher = ecc.encrypt(msg)
    hash_value = hashlib.sha256(cipher.encode()).hexdigest()



    record = {
         "sender": sender,
        "receiver": receiver,
        "plaintext": msg,
        "ciphertext": cipher,
        "hash": hash_value,
        "time": datetime.now().strftime("%H:%M")
    }
    
    chat_history[room].append(record)
    

    emit("receive_private", {
        "sender": sender,
        "plain": msg,
        "cipher": cipher,
        "hash": hash_value
    }, room=room)



# ==============================
#        ECC TOOL WEB
# ==============================

ecc_tool = ECCRoomKey()

@app.route("/ecc-tool", methods=["GET", "POST"])
def ecc_tool_page():
    plaintext = ""
    ciphertext = ""
    decrypted = ""

    if request.method == "POST":
        action = request.form.get("action")

        if action == "encrypt":
            plaintext = request.form.get("plaintext", "")
            ciphertext = ecc_tool.encrypt(plaintext)

        elif action == "decrypt":
            ciphertext = request.form.get("ciphertext", "")
            try:
                decrypted = ecc_tool.decrypt(ciphertext)
            except:
                decrypted = "❌ Không giải mã được"

    return render_template(
        "ecc_tool.html",
        plaintext=plaintext,
        ciphertext=ciphertext,
        decrypted=decrypted
    )

# ==============================
#        ECC MONITOR WEB
# ==============================
@app.route("/ecc-monitor")
def ecc_monitor():
    if "username" not in session:
        return redirect("/")

    logs = []
    for room, messages in chat_history.items():
        for m in messages:
            logs.append({
                "room": room,
                "sender": m["sender"],
                "plaintext": m["plaintext"],
                "ciphertext": m["ciphertext"],
                "hash": m["hash"],
                "time": m["time"]
            })

    return render_template("ecc_monitor.html", logs=logs)


# ==============================
#            RUN
# ==============================
if __name__ == "__main__":
    socketio.run(app, debug=True, port=5000)
