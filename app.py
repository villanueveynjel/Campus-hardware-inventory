# app.py
from __future__ import annotations

import csv
import hashlib
import io
import logging
import os
import re
import secrets
import psycopg
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, flash, jsonify, redirect, render_template, request, send_file, session, url_for

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "hardware_inventory.db"
LOG_DIR = BASE_DIR / "app_logging"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    filename=LOG_DIR / "app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "campus-hardware-inventory-dev-key-change-me")
app.config["DATABASE"] = str(DB_PATH)

PURPLE = {
    "deep": "#2B1238",
    "dark": "#432052",
    "primary": "#6A3D78",
    "primary2": "#7B4A8A",
    "accent": "#9B59B6",
    "accent_dark": "#7D3C98",
    "panel": "#E9DDF0",
    "panel2": "#F4EDF7",
    "border": "#C8B1D2",
    "text": "#2A1830",
    "white": "#FFFFFF",
    "muted": "#6E5A75",
}

MAX_QTY_BY_CATEGORY = {
    "Microcontroller": 20,
    "IC": 30,
    "Motor": 20,
    "Input Devices": 20,
    "Output Devices": 20,
    "Power Supply": 20,
    "Communication": 20,
    "Passive Components": 50,
    "Tools": 20,
    "Others": 20,
}
CATEGORIES = list(MAX_QTY_BY_CATEGORY)


def log_info(message):
    logging.info(message)


def log_warning(message):
    logging.warning(message)


def log_error(message):
    logging.error(message)


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def compute_status(quantity: int) -> str:
    if quantity > 5:
        return "In Stock"
    if quantity >= 1:
        return "Low Stock"
    return "Out of Stock"


def get_max_qty(category: str) -> int:
    if not category:
        return MAX_QTY_BY_CATEGORY["Others"]
    for key, value in MAX_QTY_BY_CATEGORY.items():
        if key.lower() == str(category).strip().lower():
            return value
    if str(category).strip().lower() == "micro":
        return MAX_QTY_BY_CATEGORY["Microcontroller"]
    return MAX_QTY_BY_CATEGORY["Others"]


class CompatRow(dict):
    """Dictionary-style row that also supports the original [0] access."""
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


def compat_row(cursor):
    def make_row(row):
        columns = [column.name for column in cursor.description]
        return CompatRow(zip(columns, row))

    return make_row


class PostgresConnection:
    """Small compatibility wrapper for the original SQLite-style db() calls."""
    def __init__(self, connection):
        self.connection = connection

    def execute(self, query, params=None):
        # Convert the original SQLite ? placeholders to psycopg %s placeholders.
        query = query.replace("?", "%s")
        if params is None:
            return self.connection.execute(query)
        return self.connection.execute(query, params)

    def __getattr__(self, name):
        return getattr(self.connection, name)


def db():
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is not set.")

    conn = psycopg.connect(database_url, row_factory=compat_row)
    return PostgresConnection(conn)


def init_db():
    """Verify that the migrated PostgreSQL database is available.

    The SQLite database was already migrated to Supabase PostgreSQL.
    This function intentionally does not recreate, reseed, or modify the
    existing application records.
    """
    required_tables = {
        "users",
        "password_resets",
        "hardware",
        "hardware_requests",
        "audit_log",
    }

    conn = db()
    try:
        rows = conn.execute(
            """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_name = ANY(%s)
            """,
            (list(required_tables),),
        ).fetchall()

        found_tables = {row["table_name"] for row in rows}
        missing_tables = required_tables - found_tables

        if missing_tables:
            raise RuntimeError(
                "Missing PostgreSQL tables: " + ", ".join(sorted(missing_tables))
            )
    finally:
        conn.close()


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def audit(username, action, item_name=None, quantity=None, request_id=None, details=""):
    conn = db()
    conn.execute(
        "INSERT INTO audit_log(username,action,item_name,quantity,request_id,details,created_at) VALUES(?,?,?,?,?,?,?)",
        (username, action, item_name, quantity, request_id, details, now_str()),
    )
    conn.commit()
    conn.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            flash("Please log in to access that page.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("Admin access is required for that page.", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped


def current_user():
    if "username" not in session:
        return None
    conn = db()
    row = conn.execute("SELECT id,username,email,role FROM users WHERE username=?", (session["username"],)).fetchone()
    conn.close()
    return row


def password_valid(password):
    return bool(re.fullmatch(r"(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}", password))


def get_inventory(search_query="", category_filter="All"):
    conn = db()
    sql = "SELECT * FROM hardware WHERE 1=1"
    params = []
    if search_query:
        sql += " AND (item_name LIKE ? OR category LIKE ?)"
        params += [f"%{search_query}%", f"%{search_query}%"]
    if category_filter and category_filter != "All":
        sql += " AND LOWER(category)=LOWER(?)"
        params.append(category_filter)
    sql += " ORDER BY item_id"
    rows = conn.execute(sql, params).fetchall()
    total_stocks = conn.execute("SELECT COALESCE(SUM(quantity),0) FROM hardware").fetchone()[0]
    conn.close()
    return rows, int(total_stocks)


def get_request(request_id):
    conn = db()
    row = conn.execute("SELECT * FROM hardware_requests WHERE request_id=?", (request_id,)).fetchone()
    conn.close()
    return row


def find_hardware(conn, item_name, category):
    return conn.execute(
        "SELECT * FROM hardware WHERE LOWER(item_name)=LOWER(?) AND LOWER(category)=LOWER(?) ORDER BY item_id LIMIT 1",
        (item_name.strip(), category.strip()),
    ).fetchone()


def generate_queue(conn):
    current = conn.execute("SELECT COALESCE(MAX(queue_number),100) FROM hardware_requests").fetchone()[0]
    return int(current) + 1


@app.context_processor
def inject_globals():
    return {"purple": PURPLE, "categories": CATEGORIES, "current_user": current_user(), "max_qty": get_max_qty}


@app.route("/")
def index():
    return redirect(url_for("dashboard" if "username" in session else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        if not identifier or not password:
            flash("Please fill in both fields.", "error")
            return render_template("login.html")
        conn = db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=? OR email=?", (identifier, identifier)
        ).fetchone()
        if not user:
            conn.close()
            log_warning(f"Login failure: unknown user {identifier}")
            flash("Invalid credentials.", "error")
            return render_template("login.html")
        if user["failed_attempts"] >= 3:
            conn.close()
            flash("Your account is locked due to 3 failed login attempts. Please use Reset / Unlock.", "error")
            return render_template("login.html")
        if user["password_hash"] == hash_password(password):
            conn.execute("UPDATE users SET failed_attempts=0 WHERE id=?", (user["id"],))
            conn.commit()
            conn.close()
            session.clear()
            session["username"] = user["username"]
            session["role"] = user["role"]
            log_info(f"Login success: {user['username']} [{user['role']}]")
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))
        attempts = user["failed_attempts"] + 1
        conn.execute("UPDATE users SET failed_attempts=? WHERE id=?", (attempts, user["id"]))
        conn.commit()
        conn.close()
        if attempts >= 3:
            flash("Account locked after 3 unsuccessful attempts. Please use Reset / Unlock.", "error")
        else:
            flash(f"Invalid credentials. You have {3-attempts} attempt(s) left before account lockout.", "error")
        log_warning(f"Login failure: {user['username']} attempt {attempts}")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not username or not email or not password or not confirm:
            flash("Provide username, email, password, and confirmation.", "error")
        elif not re.fullmatch(r"^[\w.\-+]+@[\w.\-]+\.[A-Za-z]{2,}$", email):
            flash("Please enter a valid email address format.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif not password_valid(password):
            flash("Password must be at least 8 characters long, contain an uppercase letter, a number, and a special character.", "error")
        else:
            conn = db()
            try:
                conn.execute(
                    "INSERT INTO users(username,email,password_hash,role,failed_attempts) VALUES(?,?,?,?,0)",
                    (username, email, hash_password(password), "user"),
                )
                conn.commit()
                log_info(f"Registration success: {username}")
                flash("Registration complete! You may now log in.", "success")
                return redirect(url_for("login"))
            except psycopg.errors.UniqueViolation:
                exists_username = conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
                flash("That username is already taken." if exists_username else "That email is already taken.", "error")
            finally:
                conn.close()
    return render_template("register.html")


@app.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        new_password = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not all([username, email, new_password, confirm]):
            flash("All fields are required for password reset/unlock.", "error")
        elif new_password != confirm:
            flash("New passwords do not match.", "error")
        elif not password_valid(new_password):
            flash("New password must be at least 8 characters long, contain an uppercase letter, a number, and a special character.", "error")
        else:
            conn = db()
            user = conn.execute("SELECT id FROM users WHERE username=? AND email=?", (username, email)).fetchone()
            if not user:
                flash("No user found matching that username and registered email.", "error")
            else:
                pending = conn.execute(
                    "SELECT id FROM password_resets WHERE username=? AND status='Pending'", (username,)
                ).fetchone()
                if pending:
                    flash("A password reset request for this account is already pending admin approval.", "error")
                else:
                    conn.execute(
                        "INSERT INTO password_resets(username,email,new_password,status,created_at) VALUES(?,?,?,?,?)",
                        (username, email, hash_password(new_password), "Pending", now_str()),
                    )
                    conn.commit()
                    log_info(f"Password reset request submitted: {username}")
                    flash("Password reset/unlock request submitted successfully. Awaiting Admin approval.", "success")
                    conn.close()
                    return redirect(url_for("login"))
            conn.close()
    return render_template("reset.html")


@app.route("/logout")
def logout():
    username = session.get("username")
    session.clear()
    if username:
        log_info(f"Logout: {username}")
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    search_query = request.args.get("search", "").strip()
    category_filter = request.args.get("category", "All")
    rows, total_stocks = get_inventory(search_query, category_filter)
    conn = db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (session["username"],)).fetchone()
    if session["role"] == "admin":
        borrowed_items = conn.execute("SELECT COALESCE(SUM(quantity),0) FROM hardware_requests WHERE borrow_status='Borrowed'").fetchone()[0]
        pending_borrow = conn.execute("SELECT COUNT(*) FROM hardware_requests WHERE approval_status='Pending'").fetchone()[0]
        pending_returns = conn.execute("SELECT COUNT(*) FROM hardware_requests WHERE return_status='Pending'").fetchone()[0]
        borrowed_requests = conn.execute("SELECT * FROM hardware_requests WHERE borrow_status='Borrowed' ORDER BY request_id DESC").fetchall()
    else:
        borrowed_items = conn.execute("SELECT COALESCE(SUM(quantity),0) FROM hardware_requests WHERE username=? AND borrow_status='Borrowed'", (session["username"],)).fetchone()[0]
        pending_borrow = conn.execute("SELECT COUNT(*) FROM hardware_requests WHERE username=? AND approval_status='Pending'", (session["username"],)).fetchone()[0]
        pending_returns = conn.execute("SELECT COUNT(*) FROM hardware_requests WHERE username=? AND return_status='Pending'", (session["username"],)).fetchone()[0]
        borrowed_requests = conn.execute("SELECT * FROM hardware_requests WHERE username=? AND borrow_status='Borrowed' ORDER BY request_id DESC", (session["username"],)).fetchall()
    conn.close()
    return render_template(
        "dashboard.html",
        rows=rows,
        total_stocks=total_stocks,
        borrowed_items=int(borrowed_items or 0),
        pending_borrow=int(pending_borrow or 0),
        pending_returns=int(pending_returns or 0),
        borrowed_requests=borrowed_requests,
        search_query=search_query,
        category_filter=category_filter,
        user=user,
    )


@app.route("/api/hardware")
@login_required
def hardware_api():
    """Return the current hardware catalog as JSON for the Request Form.

    Keeping catalog data out of the JavaScript block prevents Jinja template
    syntax from being mixed with JavaScript, which also removes false-positive
    editor errors in VS Code/Pylance.
    """
    conn = db()
    rows = conn.execute(
        "SELECT item_id, item_name, category, quantity, status FROM hardware ORDER BY LOWER(item_name)"
    ).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])


@app.route("/request-borrow", methods=["GET", "POST"])
@login_required
def request_borrow():
    if session["role"] == "admin":
        flash("Admin accounts do not submit student borrow requests.", "error")
        return redirect(url_for("dashboard"))
    items = get_inventory("", "All")[0]
    if request.method == "POST":
        fields = {k: request.form.get(k, "").strip() for k in ["name", "student_id", "professor", "subject", "schedule"]}
        item_names = [v.strip() for v in request.form.getlist("hardware_item") if v.strip()]
        categories = [v.strip() for v in request.form.getlist("category")]
        quantities = [v.strip() for v in request.form.getlist("quantity")]
        if not all(fields.values()) or not item_names or len(item_names) != len(categories) or len(item_names) != len(quantities):
            flash("Please fill out all student details and at least one hardware item row.", "error")
            return render_template("request_form.html", form=fields, item_names=item_names, categories_selected=categories, quantities=quantities, items=items)
        conn = db()
        validated = []
        try:
            for i, item_name in enumerate(item_names):
                category = categories[i].strip()
                raw_qty = quantities[i].strip()
                if not category or not raw_qty:
                    raise ValueError("All hardware item, category, and quantity fields are required.")
                qty = int(raw_qty)
                if qty < 1:
                    raise ValueError("Quantity must be a positive whole number.")
                max_qty = get_max_qty(category)
                if qty > max_qty:
                    raise ValueError(f"Requested quantity cannot exceed {max_qty} for {category}.")
                item = find_hardware(conn, item_name, category)
                if not item:
                    raise ValueError(f"{item_name} ({category}) is not in the Hardware Catalog.")
                if qty > item["quantity"]:
                    raise ValueError(f"Only {item['quantity']} unit(s) of {item_name} are currently available.")
                validated.append((item_name, category, qty, item["quantity"]))

            queue = generate_queue(conn)
            created = []
            for item_name, category, qty, _available in validated:
                request_row = conn.execute(
                    """INSERT INTO hardware_requests
                    (username,name,student_id,professor,subject,schedule,hardware_item,category,quantity,queue_number,approval_status,borrow_status,return_status,created_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?, 'Pending','Not Borrowed','',?)
                    RETURNING request_id""",
                    (session["username"], fields["name"], fields["student_id"], fields["professor"], fields["subject"], fields["schedule"], item_name, category, qty, queue, now_str()),
                ).fetchone()
                request_id = request_row["request_id"]
                created.append((request_id, item_name, qty))
            conn.commit()
        except (ValueError, psycopg.Error) as exc:
            conn.rollback()
            flash(str(exc) or "Unable to submit the hardware request.", "error")
            conn.close()
            return render_template("request_form.html", form=fields, item_names=item_names, categories_selected=categories, quantities=quantities, items=items)
        conn.close()
        for request_id, item_name, qty in created:
            audit(session["username"], "Borrow request submitted", item_name, qty, request_id, f"Queue Q-{queue}")
        flash(f"Hardware request successfully submitted with {len(created)} item(s). Queue number: Q-{queue}", "success")
        return redirect(url_for("requests"))
    return render_template("request_form.html", form={}, item_names=[], categories_selected=[], quantities=[], items=items)


@app.route("/requests")
@login_required
def requests():
    conn = db()
    if session["role"] == "admin":
        reqs = conn.execute("SELECT * FROM hardware_requests ORDER BY request_id DESC").fetchall()
    else:
        reqs = conn.execute("SELECT * FROM hardware_requests WHERE username=? ORDER BY request_id DESC", (session["username"],)).fetchall()
    conn.close()
    return render_template("requests.html", requests=reqs)


@app.route("/return/<int:request_id>", methods=["POST"])
@login_required
def request_return(request_id):
    conn = db()
    row = conn.execute("SELECT * FROM hardware_requests WHERE request_id=?", (request_id,)).fetchone()
    if not row:
        conn.close(); flash("Borrow record not found.", "error"); return redirect(url_for("dashboard"))
    if row["username"] != session["username"]:
        conn.close(); flash("You can only request a return for your own borrowed item.", "error"); return redirect(url_for("dashboard"))
    if row["borrow_status"] != "Borrowed":
        conn.close(); flash("Only currently borrowed items can be returned.", "error"); return redirect(url_for("dashboard"))
    if row["return_status"] == "Pending":
        conn.close(); flash("A return request is already pending for this item.", "error"); return redirect(url_for("dashboard"))
    conn.execute("UPDATE hardware_requests SET return_status='Pending' WHERE request_id=?", (request_id,))
    conn.commit(); conn.close()
    audit(session["username"], "Return requested", row["hardware_item"], row["quantity"], request_id, "Awaiting admin approval")
    flash("Return request submitted. Stock will not be restored until Admin approval.", "success")
    return redirect(url_for("dashboard"))


@app.route("/admin/approvals")
@admin_required
def approvals():
    conn = db()
    pending_borrows = conn.execute("SELECT * FROM hardware_requests WHERE approval_status='Pending' ORDER BY request_id DESC").fetchall()
    pending_returns = conn.execute("SELECT * FROM hardware_requests WHERE return_status='Pending' ORDER BY request_id DESC").fetchall()
    pending_resets = conn.execute("SELECT id,username,email,created_at FROM password_resets WHERE status='Pending' ORDER BY id DESC").fetchall()
    inventory = conn.execute("SELECT item_name,category,quantity FROM hardware ORDER BY item_id").fetchall()
    conn.close()
    return render_template("approvals.html", pending_borrows=pending_borrows, pending_returns=pending_returns, pending_resets=pending_resets, inventory=inventory)


@app.route("/admin/borrow/<int:request_id>/<action>", methods=["POST"])
@admin_required
def process_borrow(request_id, action):
    if action not in ("approve", "reject"):
        flash("Invalid approval action.", "error"); return redirect(url_for("approvals"))
    conn = db()
    try:
        conn.execute("BEGIN")
        row = conn.execute("SELECT * FROM hardware_requests WHERE request_id=?", (request_id,)).fetchone()
        if not row or row["approval_status"] != "Pending":
            conn.rollback(); flash("This borrow request is no longer pending.", "error"); return redirect(url_for("approvals"))
        if action == "reject":
            conn.execute("UPDATE hardware_requests SET approval_status='Rejected', approval_code='N/A' WHERE request_id=?", (request_id,))
            conn.commit()
            audit(session["username"], "Borrow request rejected", row["hardware_item"], row["quantity"], request_id, f"Requester: {row['username']}")
            flash("Borrow request rejected. Stock was not changed.", "success")
            return redirect(url_for("approvals"))
        item = find_hardware(conn, row["hardware_item"], row["category"])
        if not item:
            conn.rollback(); flash("The requested hardware no longer exists in the catalog.", "error"); return redirect(url_for("approvals"))
        if row["quantity"] > item["quantity"]:
            conn.rollback(); flash(f"Cannot approve: only {item['quantity']} unit(s) remain available.", "error"); return redirect(url_for("approvals"))
        new_qty = item["quantity"] - row["quantity"]
        code = f"APP-{secrets.randbelow(90000)+10000}"
        conn.execute("UPDATE hardware SET quantity=?, status=? WHERE item_id=?", (new_qty, compute_status(new_qty), item["item_id"]))
        conn.execute("UPDATE hardware_requests SET approval_status='Approved', approval_code=?, borrow_status='Borrowed', time_checkin=? WHERE request_id=?", (code, now_str(), request_id))
        conn.commit()
        audit(session["username"], "Borrow request approved", row["hardware_item"], row["quantity"], request_id, f"Approval {code}; stock {item['quantity']} -> {new_qty}")
        flash(f"Borrow approved. Approval code: {code}. Stock decreased by {row['quantity']}.", "success")
    except Exception as exc:
        conn.rollback(); log_error(f"Borrow approval error: {exc}"); flash("Unable to process the borrow approval.", "error")
    finally:
        conn.close()
    return redirect(url_for("approvals"))


@app.route("/admin/return/<int:request_id>/<action>", methods=["POST"])
@admin_required
def process_return(request_id, action):
    if action not in ("approve", "reject"):
        flash("Invalid return action.", "error"); return redirect(url_for("approvals"))
    conn = db()
    try:
        conn.execute("BEGIN")
        row = conn.execute("SELECT * FROM hardware_requests WHERE request_id=?", (request_id,)).fetchone()
        if not row or row["return_status"] != "Pending" or row["borrow_status"] != "Borrowed":
            conn.rollback(); flash("This return request is no longer pending.", "error"); return redirect(url_for("approvals"))
        if action == "reject":
            conn.execute("UPDATE hardware_requests SET return_status='Rejected' WHERE request_id=?", (request_id,))
            conn.commit()
            audit(session["username"], "Return rejected", row["hardware_item"], row["quantity"], request_id, "Item remains borrowed")
            flash("Return rejected. The item remains borrowed and stock was not changed.", "success")
            return redirect(url_for("approvals"))
        item = find_hardware(conn, row["hardware_item"], row["category"])
        if not item:
            conn.rollback(); flash("The hardware item no longer exists in the catalog.", "error"); return redirect(url_for("approvals"))
        max_qty = get_max_qty(item["category"])
        new_qty = item["quantity"] + row["quantity"]
        if new_qty > max_qty:
            conn.rollback(); flash(f"Cannot approve return: stock would exceed the category maximum of {max_qty}.", "error"); return redirect(url_for("approvals"))
        conn.execute("UPDATE hardware SET quantity=?, status=? WHERE item_id=?", (new_qty, compute_status(new_qty), item["item_id"]))
        conn.execute("UPDATE hardware_requests SET return_status='Approved', borrow_status='Returned', time_checkout=? WHERE request_id=?", (now_str(), request_id))
        conn.commit()
        audit(session["username"], "Return approved", row["hardware_item"], row["quantity"], request_id, f"Stock {item['quantity']} -> {new_qty}")
        flash(f"Return approved. Stock restored by {row['quantity']}.", "success")
    except Exception as exc:
        conn.rollback(); log_error(f"Return approval error: {exc}"); flash("Unable to process the return approval.", "error")
    finally:
        conn.close()
    return redirect(url_for("approvals"))


@app.route("/admin/reset/<int:reset_id>/<action>", methods=["POST"])
@admin_required
def process_reset(reset_id, action):
    if action not in ("approve", "reject"):
        flash("Invalid reset action.", "error"); return redirect(url_for("approvals"))
    conn = db()
    row = conn.execute("SELECT * FROM password_resets WHERE id=? AND status='Pending'", (reset_id,)).fetchone()
    if not row:
        conn.close(); flash("Password reset request not found or already processed.", "error"); return redirect(url_for("approvals"))
    if action == "approve":
        conn.execute("UPDATE users SET password_hash=?, failed_attempts=0 WHERE username=? AND email=?", (row["new_password"], row["username"], row["email"]))
        conn.execute("UPDATE password_resets SET status='Approved' WHERE id=?", (reset_id,))
        message = f"Password reset approved and account unlocked for {row['username']}."
    else:
        conn.execute("UPDATE password_resets SET status='Rejected' WHERE id=?", (reset_id,))
        message = "Password reset request rejected."
    conn.commit(); conn.close()
    audit(session["username"], f"Password reset {action}d", None, None, None, f"Target: {row['username']}")
    flash(message, "success")
    return redirect(url_for("approvals"))


@app.route("/inventory/update/<int:item_id>", methods=["POST"])
@admin_required
def update_inventory(item_id):
    raw_qty = request.form.get("quantity", "").strip()
    try:
        qty = int(raw_qty)
        if qty < 0:
            raise ValueError
    except ValueError:
        flash("Quantity must be a whole number of 0 or more.", "error")
        return redirect(url_for("dashboard"))
    conn = db()
    item = conn.execute("SELECT * FROM hardware WHERE item_id=?", (item_id,)).fetchone()
    if not item:
        conn.close(); flash("Hardware item not found.", "error"); return redirect(url_for("dashboard"))
    max_qty = get_max_qty(item["category"])
    if qty > max_qty:
        conn.close(); flash(f"Quantity cannot exceed {max_qty} for {item['category']}.", "error"); return redirect(url_for("dashboard"))
    conn.execute("UPDATE hardware SET quantity=?, status=? WHERE item_id=?", (qty, compute_status(qty), item_id))
    conn.commit(); conn.close()
    audit(session["username"], "Inventory quantity updated", item["item_name"], qty, None, f"Admin set stock to {qty}")
    flash("Hardware quantity updated successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/inventory/delete/<int:item_id>", methods=["POST"])
@admin_required
def delete_inventory(item_id):
    conn = db(); item = conn.execute("SELECT * FROM hardware WHERE item_id=?", (item_id,)).fetchone()
    if not item:
        conn.close(); flash("Hardware item not found.", "error"); return redirect(url_for("dashboard"))
    active = conn.execute("SELECT COUNT(*) FROM hardware_requests WHERE hardware_item=? AND category=? AND borrow_status='Borrowed'", (item["item_name"], item["category"])).fetchone()[0]
    if active:
        conn.close(); flash("This item cannot be deleted while it has an active borrowed record.", "error"); return redirect(url_for("dashboard"))
    conn.execute("DELETE FROM hardware WHERE item_id=?", (item_id,)); conn.commit(); conn.close()
    audit(session["username"], "Inventory item deleted", item["item_name"], item["quantity"], None, "Catalog record deleted")
    flash("Hardware record deleted successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/inventory/add", methods=["POST"])
@admin_required
def add_inventory():
    name = request.form.get("item_name", "").strip()
    category = request.form.get("category", "").strip()
    raw_qty = request.form.get("quantity", "").strip()
    if not name or not category or not raw_qty:
        flash("Item name, category, and quantity are required.", "error"); return redirect(url_for("dashboard"))
    try: qty = int(raw_qty)
    except ValueError: flash("Quantity must be a whole number.", "error"); return redirect(url_for("dashboard"))
    max_qty = get_max_qty(category)
    if qty < 0 or qty > max_qty:
        flash(f"Quantity must be between 0 and {max_qty} for {category}.", "error"); return redirect(url_for("dashboard"))
    conn = db()
    try:
        conn.execute("INSERT INTO hardware(item_name,category,quantity,unit_price,status) VALUES(?,?,?,?,?)", (name, category, qty, 0.0, compute_status(qty)))
        conn.commit()
    except psycopg.errors.UniqueViolation:
        pass
    conn.close(); audit(session["username"], "Inventory item added", name, qty, None, category)
    flash("Hardware item added successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not current or not new or not confirm:
            flash("All fields are required.", "error")
        elif new != confirm:
            flash("New passwords do not match.", "error")
        elif not password_valid(new):
            flash("New password must be at least 8 characters long, contain an uppercase letter, a number, and a special character.", "error")
        else:
            conn = db(); user = conn.execute("SELECT password_hash FROM users WHERE username=?", (session["username"],)).fetchone()
            if not user or user["password_hash"] != hash_password(current):
                flash("Incorrect current password.", "error")
            else:
                conn.execute("UPDATE users SET password_hash=? WHERE username=?", (hash_password(new), session["username"]))
                conn.commit(); flash("Password successfully updated!", "success"); audit(session["username"], "Password changed")
            conn.close()
    return render_template("profile.html")


@app.route("/history")
@login_required
def history():
    conn = db()
    if session["role"] == "admin":
        reqs = conn.execute("SELECT * FROM hardware_requests ORDER BY request_id DESC").fetchall()
        logs = conn.execute("SELECT * FROM audit_log ORDER BY id DESC").fetchall()
    else:
        reqs = conn.execute("SELECT * FROM hardware_requests WHERE username=? ORDER BY request_id DESC", (session["username"],)).fetchall()
        logs = conn.execute("SELECT * FROM audit_log WHERE username=? ORDER BY id DESC", (session["username"],)).fetchall()
    conn.close()
    return render_template("history.html", requests=reqs, logs=logs)


@app.route("/export/csv")
@login_required
def export_csv():
    conn = db()
    rows = conn.execute("SELECT item_id,item_name,category,quantity,unit_price,status FROM hardware ORDER BY item_id").fetchall()
    conn.close()
    out = io.StringIO(); writer = csv.writer(out)
    writer.writerow(["Item ID", "Item Name", "Category", "Max Qty", "Available Qty", "Unit Price ($)", "Status"])
    for row in rows:
        writer.writerow([row["item_id"], row["item_name"], row["category"], get_max_qty(row["category"]), row["quantity"], row["unit_price"], row["status"]])
    data = io.BytesIO(out.getvalue().encode("utf-8")); data.seek(0)
    return send_file(data, mimetype="text/csv", as_attachment=True, download_name="inventory_report.csv")


@app.after_request
def no_cache_protected(response):
    if request.endpoint not in {"login", "register", "reset", "static"}:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response



if __name__ == "__main__":
    init_db()
    print("\n" + "=" * 55)
    print("  LABORATORY SYSTEM WEB APPLICATION")
    print("  Open this link in Chrome:")
    print("  http://127.0.0.1:5000")
    print("=" * 55)
    app.run(host="127.0.0.1", port=5000, debug=False)