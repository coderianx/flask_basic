from flask import Flask, render_template, session, request, redirect, url_for
from dotenv import load_dotenv
import sqlite3
import os
import bcrypt

app = Flask(__name__, template_folder="frontend")

load_dotenv()
secret_key = os.getenv("SECRET_KEY", "default_secret_key")
app.secret_key = secret_key

def get_db():
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn

# DB oluşturma
with get_db() as conn:
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password BLOB
    )
    """)
    conn.commit()

@app.route("/")
def root():
    return "Go /login or /register"

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        password_bytes = password.encode("utf-8")
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return "Bu kullanıcı adı zaten alınmış ❌"
        finally:
            conn.close()

        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user is None:
            return "Kullanıcı bulunamadı ❌"

        if bcrypt.checkpw(password.encode("utf-8"), user["password"]):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("profile", username=username))
        else:
            return "Şifre yanlış ❌"

    return render_template("login.html")

# Herkes herkesin profilini görebilir
@app.route("/@<username>")
def profile(username):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user is None:
        return "Kullanıcı bulunamadı ❌"

    logged_in_user = session.get("username")  # Giriş yapmış kullanıcı
    return render_template("profile.html", user=user, logged_in_user=logged_in_user)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
