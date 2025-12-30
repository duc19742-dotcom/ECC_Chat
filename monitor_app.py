from flask import Flask, render_template
import json, os

app = Flask(__name__, template_folder="templates")

LOG_FILE = "chat_logs.json"

@app.route("/")
def monitor():
    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except:
            logs = []

    return render_template("ecc_monitor.html", logs=logs)

if __name__ == "__main__":
    app.run(debug=True, port=5001)
