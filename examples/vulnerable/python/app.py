"""DELIBERATELY VULNERABLE Flask app used to demo and test Argus. Do not deploy."""

import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, redirect, request, send_file

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key-123"


def db():
    return sqlite3.connect("app.db")


@app.route("/user")
def get_user():
    # SQL injection via f-string
    name = request.args.get("name")
    cur = db().cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return {"rows": cur.fetchall()}


@app.route("/user/safe")
def get_user_safe():
    # Safe: parameterised (should NOT be reported)
    name = request.args.get("name")
    cur = db().cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return {"rows": cur.fetchall()}


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return out


@app.route("/session", methods=["POST"])
def load_session():
    return pickle.loads(request.data)


@app.route("/config", methods=["POST"])
def load_config():
    return yaml.load(request.data)


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr", "1+1")))


@app.route("/download")
def download():
    filename = request.args.get("file")
    return send_file(os.path.join("/srv/files", request.args.get("file")))


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return requests.get(url, timeout=5).text


@app.route("/login-redirect")
def login_redirect():
    return redirect(request.args.get("next"))


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def call_partner_api():
    return requests.get("https://partner.example.com/api", verify=False)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
