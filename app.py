from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = "dev_secret_key"

FLAG = "IET{pr3d1ct1ng_f41lur3_cr34t3$_1t}"

# NEW LOGIN PASSWORD (from your XOR challenge plaintext)
LOGIN_PASSWORD = "FLAG{n!c3_tr&_but_n0p3_n0t_th3_fl@g}"
ALLOWED_ROLES = {"user", "moderator", "admin"}

HINTS = [
    "Not all security flaws come from malicious input. Sometimes the system behaves exactly as designed.",
    "Pay close attention to what the client sends to the server. Ask which values should never be trusted.",
    "Messages and status indicators do not always reflect real system state. Verify access instead of trusting UI."
]

def init_session():
    if "logged_in" not in session:
        session["logged_in"] = False
    if "role" not in session:
        session["role"] = "user"
        session["requests"] = []
        session["count"] = 0

@app.route("/", methods=["GET", "POST"])
def login():
    init_session()
    error = None

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Username is anything; password must match the decoded value
        if username and password == LOGIN_PASSWORD:
            session.clear()
            session["logged_in"] = True
            session["username"] = username
            session["role"] = "user"
            session["requests"] = []
            session["count"] = 0
            return redirect(url_for("profile"))
        else:
            error = "Invalid credentials"

    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/profile", methods=["GET", "POST"])
def profile():
    init_session()
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    if request.method == "POST":
        requested_role_raw = request.form.get("role", "")
        requested_role = requested_role_raw.strip().lower()
        current_role = session["role"]
        
        session["count"] += 1
        
        # ✅ Validate role
        if requested_role not in ALLOWED_ROLES:
            session["requests"].append({
                "requested": requested_role_raw,
                "status": "Invalid Role"
            })
            return render_template(
                "profile.html",
                role=session["role"],
                error="Invalid role. Allowed roles: user, moderator, admin."
            )
        
        # ❌ Keep your intentional bug exactly the same
        if requested_role == current_role:
            session["role"] = "admin"
        
        session["requests"].append({
            "requested": requested_role,
            "status": "Pending"
        })
        
        return redirect(url_for("status"))


    return render_template("profile.html", role=session["role"])

@app.route("/status")
def status():
    init_session()
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    hint = None
    # FIXED: don't show hint at 0 requests
    if session["count"] > 0 and session["count"] % 3 == 0:
        index = (session["count"] // 3) - 1
        if index < len(HINTS):
            hint = HINTS[index]

    return render_template(
        "status.html",
        requests=session["requests"],
        hint=hint
    )

@app.route("/admin")
def admin():
    init_session()
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    if session["role"] != "admin":
        return render_template("no_access.html")

    return render_template("admin.html", flag=FLAG)

if __name__ == "__main__":
    app.run()

