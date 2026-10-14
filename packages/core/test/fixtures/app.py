# llmscan テスト用フィクスチャ（意図的に脆弱なコード）
# 「expect: ルールID」のある行に指摘が出ること、それ以外の行に出ないことを検証する
import os
import pickle
import sqlite3
import subprocess

import yaml
from anthropic import Anthropic
from fastapi import Depends, FastAPI
from flask import Flask, Markup, render_template_string, request
from openai import OpenAI

app = Flask(__name__)
api = FastAPI()
client = OpenAI()
llm_client = Anthropic()


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = " + user_id)  # expect: PY-SQLI-001
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")  # expect: PY-SQLI-001
    cur.execute("SELECT * FROM users WHERE id = %s" % user_id)  # expect: PY-SQLI-001
    cur.execute("SELECT * FROM users WHERE id = {}".format(user_id))  # expect: PY-SQLI-001
    # 安全：プレースホルダ
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    # 安全：数値に変換済み
    cur.execute("SELECT * FROM users WHERE id = " + str(int(user_id)))
    return "ok"


@app.route("/ping")
def ping():
    host = request.form["host"]
    os.system("ping -c 1 " + host)  # expect: PY-CMDI-001
    subprocess.run("ping -c 1 " + host, shell=True)  # expect: PY-CMDI-001
    # 安全：シェルを使わず引数をリストで渡す
    subprocess.run(["ping", "-c", "1", host])
    return "ok"


@app.route("/calc")
def calc():
    expr = request.args["expr"]
    return str(eval(expr))  # expect: PY-CODEI-001


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)  # expect: PY-DESER-001
    conf = yaml.load(request.data)  # expect: PY-DESER-001
    safe = yaml.load(request.data, Loader=yaml.SafeLoader)
    return str((obj, conf, safe))


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    page = render_template_string("<h1>Hello " + name + "</h1>")  # expect: PY-SSTI-001
    return Markup("<b>%s</b>" % name) + page  # expect: PY-XSS-001


@api.get("/items")
async def items(q: str, limit: int = 10, db=Depends(lambda: None)):
    conn = sqlite3.connect("app.db")
    conn.execute(f"SELECT * FROM items WHERE name LIKE '%{q}%' LIMIT {limit}")  # expect: PY-SQLI-001


def ask_and_run(question: str):
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": question}],
    )
    code = resp.choices[0].message.content
    exec(code)  # expect: LLM05-CODEI-001
    sql = resp.choices[0].message.content.strip()
    sqlite3.connect("app.db").execute(sql)  # expect: LLM05-SQLI-001


def agent_tool(prompt: str):
    msg = llm_client.messages.create(model="example-model", max_tokens=1024, messages=[{"role": "user", "content": prompt}])
    for block in msg.content:
        if block.type == "tool_use":
            subprocess.run(block.input["command"], shell=True)  # expect: LLM05-CMDI-001


ALLOWED_TABLES = {"users", "orders"}


@app.route("/count")
def count():
    t = request.args.get("t", "users")
    table = t if t in ALLOWED_TABLES else "users"
    # 許可リストで検証済み
    sqlite3.connect("app.db").execute("SELECT COUNT(*) FROM " + table)
    return "ok"


def report(table: str):
    # 関数の引数を連結して SQL を組み立てる：呼び出し元次第で危険（確信度 medium）
    conn = sqlite3.connect("app.db")
    conn.execute("SELECT * FROM " + table)  # expect: PY-SQLI-001


def run_query(query: str):
    # 引数をそのまま渡すだけ：確信度 low のため既定では表示しない
    conn = sqlite3.connect("app.db")
    conn.execute(query)


@app.route("/suppressed")
def suppressed():
    table = request.args["t"]
    conn = sqlite3.connect("app.db")
    # llmscan-ignore[PY-SQLI-001]: t は許可リストで検証済み（validate_table）
    conn.execute("SELECT * FROM " + table)
    # llmscan-ignore[PY-SQLI-001]  # expect: LLMSCAN-SUPPRESS-001
    conn.execute("SELECT * FROM " + table)  # expect: PY-SQLI-001
    return "ok"
