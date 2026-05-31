from flask import Flask, render_template, jsonify
import json
import os

app = Flask(__name__)

GTFOBINS = [
    "bash", "sh", "python", "python3", "perl", "ruby", "nc", "netcat",
    "nmap", "vim", "vi", "less", "more", "man", "find", "awk", "sed",
    "tar", "zip", "gzip", "curl", "wget", "git", "gcc", "make",
    "dd", "cp", "mv", "chmod", "chown", "sudo", "su", "env",
    "xargs", "tee", "cut", "sort", "uniq", "head", "tail", "cat",
    "strace", "ltrace", "gdb", "node", "php", "ruby", "lua", "tcl",
    "expect", "socat", "openssl", "ssh", "scp", "rsync", "docker",
    "kubectl", "ansible", "puppet", "chef"
]

@app.route("/")
def index():
    return render_template("index.html", gtfobins=GTFOBINS)

@app.route("/api/gtfobins")
def api_gtfobins():
    return jsonify({"binaries": GTFOBINS, "count": len(GTFOBINS)})

@app.route("/api/status")
def api_status():
    return jsonify({
        "status": "running",
        "monitored_binaries": len(GTFOBINS),
        "detection_mode": "behavioral",
        "platform": "Linux"
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
