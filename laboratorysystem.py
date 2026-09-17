# laboratorysystem.py

import logging
import os

# --- Setup Audit Logging ---
if not os.path.exists("app_logging"):
    os.makedirs("app_logging")

logging.basicConfig(
    filename="app_logging/app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def log_info(message):
    logging.info(message)


def log_warning(message):
    logging.warning(message)


def log_error(message):
    logging.error(message)


# ============================================================
# MERGED FROM: LAB ACT 6=midterms/models/database.py
# ============================================================
# models/database.py

import sqlite3
import hashlib


def init_db(db_name="hardware_inventory.db"):
    """Create the database and tables if they don't exist."""
    try:
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        # 1. USER AUTHENTICATION TABLE
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                failed_attempts INTEGER DEFAULT 0
            )
        """
        )

        # 2. PASSWORD RESET REQUESTS TABLE
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                new_password TEXT NOT NULL,
                status TEXT DEFAULT 'Pending'
            )
        """
        )

        # 3. HARDWARE INVENTORY TABLE
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS hardware (
                item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_name TEXT NOT NULL,
                category TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                unit_price REAL NOT NULL,
                status TEXT NOT NULL
            )
        """
        )

        # 4. HARDWARE REQUESTS & QUEUE TABLE (NEW)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS hardware_requests (
                request_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                name TEXT NOT NULL,
                student_id TEXT NOT NULL,
                professor TEXT NOT NULL,
                subject TEXT NOT NULL,
                schedule TEXT NOT NULL,
                hardware_item TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                queue_number INTEGER NOT NULL,
                approval_status TEXT DEFAULT 'Queuing',
                approval_code TEXT DEFAULT '',
                time_checkin TEXT DEFAULT '',
                time_checkout TEXT DEFAULT ''
            )
        """
        )

        # Insert a default admin user if none exists
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            default_pass = hashlib.sha256("Admin123@".encode("utf-8")).hexdigest()
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role, failed_attempts) VALUES (?, ?, ?, ?, ?)",
                ("admin", "admin@campus.edu", default_pass, "admin", 0),
            )

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database initialization error: {e}")


def get_connection():
    return sqlite3.connect("hardware_inventory.db")


# ============================================================
# MERGED FROM: LAB ACT 6=midterms/models/schemas.py
# ============================================================
# models/schemas.py
def compute_status(quantity):
    if quantity > 5:
        return "In Stock"
    elif 1 <= quantity <= 5:
        return "Low Stock"
    else:
        return "Out of Stock"


# ============================================================
# MERGED FROM: LAB ACT 6=midterms/controllers/auth_controller.py
# ============================================================
# controllers/auth_controller.py

import re
import hashlib


class AuthController:

    @staticmethod
    def _hash_password(password):
        """Helper method to securely hash passwords using SHA-256."""
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    @staticmethod
    def initialize_default_admin():
        """Awtomatikong gagawa ng default admin account kung wala pa sa database."""
        conn = get_connection()
        cursor = conn.cursor()
        
        # Suriin kung meron nang username na 'admin'
        cursor.execute("SELECT id FROM users WHERE username = ?", ("admin",))
        admin_user = cursor.fetchone()
        
        if not admin_user:
            # I-hash ang default password (halimbawa: admin123)
            # Tandaan: Dapat pumasa rin ito sa password complexity rules mo kung mahigpit ang validation, 
            # o maaari mong direktang i-insert ang hash kung gusto mo ng mas simpleng password.
            hashed_pass = AuthController._hash_password("Admin@123")
            
            try:
                cursor.execute(
                    """
                    INSERT INTO users (username, email, password_hash, role, failed_attempts) 
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    ("admin", "admin@campus.com", hashed_pass, "admin", 0)
                )
                conn.commit()
                log_info("Default Admin Account Created: Username 'admin'.")
            except Exception as e:
                log_warning(f"Error creating default admin: {e}")
        
        conn.close()

    @staticmethod
    def authenticate(identifier, password):
        if not identifier or not password:
            log_warning("Validation Failure: Empty login fields attempted.")
            return False, "Please fill in both fields.", None

        hashed_password = AuthController._hash_password(password)

        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id, username, password_hash, role, failed_attempts FROM users WHERE username = ? OR email = ?",
            (identifier, identifier),
        )
        user = cursor.fetchone()

        if not user:
            conn.close()
            log_warning(f"Authentication Failure: User '{identifier}' not found.")
            return False, "Invalid credentials.", None

        user_id, db_username, db_password_hash, role, failed_attempts = user

        if failed_attempts >= 3:
            conn.close()
            log_warning(f"Authentication Failure: Account '{db_username}' is locked due to multiple failed attempts.")
            return False, "Your account is locked due to 3 failed login attempts. Please use Reset / Unlock.", None

        if db_password_hash == hashed_password:
            cursor.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user_id,))
            conn.commit()
            conn.close()

            log_info(f"Authentication Success: User '{db_username}' logged in with role '{role}'.")
            return True, "Login successful.", role
        else:
            failed_attempts += 1
            cursor.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (failed_attempts, user_id))
            conn.commit()
            conn.close()

            if failed_attempts >= 3:
                log_warning(f"Security Lockout: Account '{db_username}' locked after 3 failed attempts.")
                return False, "Account locked after 3 unsuccessful attempts. Please use Reset / Unlock.", None

            attempts_left = 3 - failed_attempts
            log_warning(f"Authentication Failure: Invalid password for '{db_username}'. {attempts_left} attempt(s) left.")
            return False, f"Invalid credentials. You have {attempts_left} attempt(s) left before account lockout.", None

    @staticmethod
    def register(username, email, password):
        if not username or not email or not password:
            log_warning("Validation Failure: Empty registration fields attempted.")
            return False, "Provide username, email, and password to register."

        email_pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        if not re.match(email_pattern, email):
            log_warning(f"Registration Failure: Invalid email format '{email}'.")
            return False, "Please enter a valid email address format."

        password_pattern = (
            r"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
        )
        if not re.match(password_pattern, password):
            log_warning("Registration Failure: Password complexity requirements not met.")
            return (
                False,
                "Password must be at least 8 characters long, contain at least one uppercase letter, one number, and one special character.",
            )

        conn = get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                log_warning(f"Registration Failure: Username '{username}' already exists.")
                return False, "That username is already taken. Choose another."

            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
            if cursor.fetchone():
                log_warning(f"Registration Failure: Email '{email}' already exists.")
                return False, "That email is already taken. Choose another."

            hashed_password = AuthController._hash_password(password)
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role, failed_attempts) VALUES (?, ?, ?, 'user', 0)",
                (username, email, hashed_password),
            )
            conn.commit()
            log_info(f"Registration Success: New user '{username}' created.")
            return True, "Registration complete! You may now log in."
        except Exception as e:
            log_warning(f"Registration Error: {e}")
            return False, "An unexpected error occurred during registration."
        finally:
            conn.close()

    @staticmethod
    def submit_password_reset(username, email, new_pass, confirm_pass):
        if not username or not email or not new_pass or not confirm_pass:
            return False, "All fields are required for password reset/unlock."
        if new_pass != confirm_pass:
            return False, "New passwords do not match."

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ? AND email = ?", (username, email))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return False, "No user found matching that username and registered email."

        hashed_new_pass = AuthController._hash_password(new_pass)
        cursor.execute(
            "INSERT INTO password_resets (username, email, new_password, status) VALUES (?, ?, ?, 'Pending')",
            (username, email, hashed_new_pass),
        )
        conn.commit()
        conn.close()
        log_info(f"Password Reset Request Submitted for user '{username}'.")
        return True, "Password reset/unlock request submitted successfully. Awaiting Admin approval."

    @staticmethod
    def fetch_pending_resets():
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email FROM password_resets WHERE status = 'Pending'")
        rows = cursor.fetchall()
        conn.close()
        return rows

    @staticmethod
    def handle_reset_approval(request_id, approve):
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username, new_password FROM password_resets WHERE id = ?", (request_id,))
        req = cursor.fetchone()
        if not req:
            conn.close()
            return False, "Request not found."

        username, new_password = req
        if approve:
            cursor.execute(
                "UPDATE users SET password_hash = ?, failed_attempts = 0 WHERE username = ?",
                (new_password, username),
            )
            cursor.execute("UPDATE password_resets SET status = 'Approved' WHERE id = ?", (request_id,))
            conn.commit()
            conn.close()
            log_info(f"Admin Approval: Password reset request approved for '{username}'. Account unlocked.")
            return True, f"Request approved. Password updated and account unlocked for '{username}'."
        else:
            cursor.execute("UPDATE password_resets SET status = 'Rejected' WHERE id = ?", (request_id,))
            conn.commit()
            conn.close()
            log_info(f"Admin Approval: Password reset request rejected for '{username}'.")
            return True, "Password reset request rejected."

    @staticmethod
    def update_password_direct(username, current_password, new_password):
        if not username or not current_password or not new_password:
            return False, "All fields are required."

        password_pattern = r"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
        if not re.match(password_pattern, new_password):
            log_warning("Password Change Failure: New password complexity requirements not met.")
            return False, "New password must be at least 8 characters long, contain an uppercase letter, a number, and a special character."

        hashed_current = AuthController._hash_password(current_password)
        hashed_new = AuthController._hash_password(new_password)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if not user or user[0] != hashed_current:
            conn.close()
            log_warning(f"Password Change Failure: Incorrect current password for '{username}'.")
            return False, "Incorrect current password."

        cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", (hashed_new, username))
        conn.commit()
        conn.close()

        log_info(f"Password Change Success: User '{username}' updated their password successfully.")
        return True, "Password successfully updated!"


# ============================================================
# MERGED FROM: LAB ACT 6=midterms/controllers/inventory_controller.py
# ============================================================
# controllers/inventory_controller.py

import csv
import random



class InventoryController:
    # Fixed maximum quantity for each hardware category.
    # These values are easy to change if your required inventory limits change.
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

    CATEGORIES = list(MAX_QTY_BY_CATEGORY.keys())

    @staticmethod
    def get_max_qty(category):
        """Return the fixed maximum quantity for a category."""
        if not category:
            return InventoryController.MAX_QTY_BY_CATEGORY["Others"]

        # Exact match first.
        if category in InventoryController.MAX_QTY_BY_CATEGORY:
            return InventoryController.MAX_QTY_BY_CATEGORY[category]

        # Case-insensitive match.
        for key, value in InventoryController.MAX_QTY_BY_CATEGORY.items():
            if key.lower() == str(category).strip().lower():
                return value

        # Compatibility with the old category name used by the original data.
        old_category = str(category).strip().lower()
        if old_category == "micro":
            return InventoryController.MAX_QTY_BY_CATEGORY["Microcontroller"]

        return InventoryController.MAX_QTY_BY_CATEGORY["Others"]

    @staticmethod
    def _find_hardware(cursor, item_name, category=None):
        """Find one hardware record by item name."""
        if category:
            cursor.execute(
                """
                SELECT item_id, item_name, category, quantity, unit_price, status
                FROM hardware
                WHERE LOWER(item_name) = LOWER(?) AND LOWER(category) = LOWER(?)
                ORDER BY item_id ASC
                LIMIT 1
                """,
                (item_name.strip(), category.strip())
            )
        else:
            cursor.execute(
                """
                SELECT item_id, item_name, category, quantity, unit_price, status
                FROM hardware
                WHERE LOWER(item_name) = LOWER(?)
                ORDER BY item_id ASC
                LIMIT 1
                """,
                (item_name.strip(),)
            )

        return cursor.fetchone()

    @staticmethod
    def ensure_item(name, category):
        """
        Make sure an item exists in the shared inventory.

        A new item starts with the fixed maximum quantity for its category.
        Existing items keep their current available quantity.
        """
        if not name or not category:
            return False, "Hardware item and category are required."

        max_qty = InventoryController.get_max_qty(category)

        conn = get_connection()
        cursor = conn.cursor()

        existing = InventoryController._find_hardware(
            cursor,
            name,
            category
        )

        if existing:
            conn.close()
            return True, "Hardware item already exists."

        status = compute_status(max_qty)

        cursor.execute(
            """
            INSERT INTO hardware
                (item_name, category, quantity, unit_price, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (name.strip(), category.strip(), max_qty, 0.0, status)
        )

        conn.commit()
        conn.close()

        log_info(
            f"Inventory Item Created: '{name}' / '{category}' "
            f"with maximum and available quantity {max_qty}."
        )

        return True, "Hardware item added to shared inventory."

    @staticmethod
    def add_item(name, category, qty_str, price_str):
        """
        Original add-item function kept for compatibility.

        The quantity cannot be higher than the fixed maximum for the
        selected category.
        """
        if not name or not category or not qty_str or not price_str:
            log_warning("Validation Failure: Incomplete hardware form submission.")
            return False, "All input fields must be properly populated."

        try:
            quantity = int(qty_str)
            unit_price = float(price_str)

            if quantity < 0 or unit_price < 0:
                raise ValueError
        except ValueError:
            log_warning(
                "Validation Failure: Invalid data types for Qty or Unit Price."
            )
            return (
                False,
                "Quantity must be a valid integer and Unit Price a valid number.",
            )

        max_qty = InventoryController.get_max_qty(category)

        if quantity > max_qty:
            return (
                False,
                f"Quantity cannot exceed the maximum of {max_qty} "
                f"for category {category}."
            )

        status = compute_status(quantity)

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO hardware
                (item_name, category, quantity, unit_price, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (name.strip(), category.strip(), quantity, unit_price, status),
        )

        conn.commit()
        conn.close()

        log_info(
            f"Inventory Add Success: '{name}' added with status '{status}'."
        )

        return True, "Hardware item added successfully!"

    @staticmethod
    def update_item(item_id, qty_str, price_str):
        if not qty_str or not price_str:
            return False, "New quantity and unit price cannot be empty."

        try:
            quantity = int(qty_str)
            unit_price = float(price_str)

            if quantity < 0 or unit_price < 0:
                raise ValueError
        except ValueError:
            return (
                False,
                "Quantity must be a valid integer and Unit Price a valid number.",
            )

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT category FROM hardware WHERE item_id = ?",
            (item_id,)
        )
        row = cursor.fetchone()

        if not row:
            conn.close()
            return False, "Hardware item not found."

        category = row[0]
        max_qty = InventoryController.get_max_qty(category)

        if quantity > max_qty:
            conn.close()
            return (
                False,
                f"New quantity cannot exceed the maximum of {max_qty} "
                f"for {category}."
            )

        status = compute_status(quantity)

        cursor.execute(
            """
            UPDATE hardware
            SET quantity = ?, unit_price = ?, status = ?
            WHERE item_id = ?
            """,
            (quantity, unit_price, status, item_id),
        )

        conn.commit()
        conn.close()

        log_info(f"Inventory Update Success: Item ID {item_id} updated.")
        return True, "Hardware item successfully updated!"

    @staticmethod
    def delete_items(item_ids):
        if not item_ids:
            return False, "No items selected for deletion."

        conn = get_connection()
        cursor = conn.cursor()

        cursor.executemany(
            "DELETE FROM hardware WHERE item_id = ?",
            [(i,) for i in item_ids]
        )

        conn.commit()
        conn.close()

        log_info(
            f"Inventory Delete Success: Deleted item IDs {str(item_ids)}"
        )

        return True, "Selected hardware records successfully deleted!"

    @staticmethod
    def get_available_qty(item_name, category=None):
        """Return the current shared available quantity for an item."""
        if not item_name:
            return 0

        conn = get_connection()
        cursor = conn.cursor()

        row = InventoryController._find_hardware(
            cursor,
            item_name,
            category
        )

        conn.close()

        if not row:
            return 0

        return int(row[3])

    @staticmethod
    def fetch_inventory(search_query="", category_filter="All"):
        """
        Return:
        item_id, item_name, category, max_qty, available_qty, status
        """
        conn = get_connection()
        cursor = conn.cursor()

        query = """
            SELECT item_id, item_name, category, quantity, unit_price, status
            FROM hardware
            WHERE 1=1
        """
        params = []

        if search_query:
            query += " AND (item_name LIKE ? OR category LIKE ?)"
            params.extend([
                f"%{search_query}%",
                f"%{search_query}%"
            ])

        if category_filter and category_filter != "All":
            query += " AND LOWER(category) = LOWER(?)"
            params.append(category_filter)

        query += " ORDER BY item_id ASC"

        cursor.execute(query, params)
        raw_rows = cursor.fetchall()

        rows = []

        for row in raw_rows:
            item_id, item_name, category, quantity, unit_price, status = row

            max_qty = InventoryController.get_max_qty(category)

            rows.append(
                (
                    item_id,
                    item_name,
                    category,
                    max_qty,
                    quantity,
                    status
                )
            )

        total_val = sum(
            row[4] * raw_rows[index][4]
            for index, row in enumerate(rows)
        )

        conn.close()

        return rows, (total_val if total_val else 0.0)

    @staticmethod
    def export_to_csv():
        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT item_id, item_name, category, quantity, unit_price, status
                FROM hardware
                """
            )

            rows = cursor.fetchall()
            conn.close()

            with open(
                "inventory_report.csv",
                mode="w",
                newline="",
                encoding="utf-8"
            ) as f:
                writer = csv.writer(f)

                writer.writerow(
                    [
                        "Item ID",
                        "Item Name",
                        "Category",
                        "Max Qty Available",
                        "Available Qty Item",
                        "Unit Price ($)",
                        "Status",
                    ]
                )

                for row in rows:
                    item_id, item_name, category, quantity, unit_price, status = row

                    writer.writerow(
                        [
                            item_id,
                            item_name,
                            category,
                            InventoryController.get_max_qty(category),
                            quantity,
                            unit_price,
                            status
                        ]
                    )

            log_info(
                "Report Generation Event: Successfully exported "
                "inventory report to inventory_report.csv."
            )

            return (
                True,
                "Inventory records successfully exported to inventory_report.csv"
            )

        except Exception as e:
            log_error(
                f"Report Generation Error: Failed to export CSV due to {str(e)}"
            )
            return False, f"Failed to generate report CSV: {str(e)}"

    @staticmethod
    def export_csv_report():
        """Compatibility name used by the current Inventory View."""
        return InventoryController.export_to_csv()

    # --- REQUEST CONTROLLERS ---

    @staticmethod
    def submit_hardware_request(
        username,
        name,
        student_id,
        professor,
        subject,
        schedule,
        hardware_item,
        quantity,
        category="Others"
    ):
        if not all([
            username,
            name,
            student_id,
            professor,
            subject,
            schedule,
            hardware_item,
            quantity,
            category
        ]):
            return False, "All tabular request form fields are required."

        try:
            qty = int(quantity)
            if qty <= 0:
                raise ValueError
        except ValueError:
            return False, "Quantity must be a positive whole number."

        max_qty = InventoryController.get_max_qty(category)

        if qty > max_qty:
            return (
                False,
                f"Requested quantity cannot exceed {max_qty} "
                f"for category {category}."
            )

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT MAX(queue_number) FROM hardware_requests"
        )
        res = cursor.fetchone()
        next_q = (res[0] + 1) if res and res[0] else 101

        cursor.execute(
            """
            INSERT INTO hardware_requests
                (
                    username,
                    name,
                    student_id,
                    professor,
                    subject,
                    schedule,
                    hardware_item,
                    category,
                    quantity,
                    queue_number,
                    approval_status
                )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Queuing')
            """,
            (
                username,
                name,
                student_id,
                professor,
                subject,
                schedule,
                hardware_item,
                category,
                qty,
                next_q
            )
        )

        conn.commit()
        conn.close()

        log_info(
            f"Hardware Request submitted by user '{username}' "
            f"with Queue #Q-{next_q}"
        )

        return True, next_q

    @staticmethod
    def get_user_request(username):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                request_id,
                name,
                student_id,
                professor,
                subject,
                schedule,
                hardware_item,
                quantity,
                queue_number,
                approval_status,
                approval_code,
                time_checkin,
                time_checkout
            FROM hardware_requests
            WHERE username = ?
            ORDER BY request_id DESC
            LIMIT 1
            """,
            (username,)
        )

        row = cursor.fetchone()
        conn.close()

        return row

    @staticmethod
    def fetch_all_hardware_requests():
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                request_id,
                username,
                name,
                student_id,
                hardware_item,
                quantity,
                queue_number,
                approval_status
            FROM hardware_requests
            """
        )

        rows = cursor.fetchall()
        conn.close()

        return rows

    @staticmethod
    def process_hardware_approval(request_id, approve):
        conn = get_connection()
        cursor = conn.cursor()

        if approve:
            app_code = f"APP-{random.randint(10000, 99999)}"

            cursor.execute(
                """
                UPDATE hardware_requests
                SET approval_status = ?, approval_code = ?
                WHERE request_id = ?
                """,
                ("Approved", app_code, request_id)
            )

            conn.commit()
            conn.close()

            return (
                True,
                f"Request approved successfully. "
                f"Generated approval code: {app_code}"
            )

        cursor.execute(
            """
            UPDATE hardware_requests
            SET approval_status = 'Rejected', approval_code = 'N/A'
            WHERE request_id = ?
            """,
            (request_id,)
        )

        conn.commit()
        conn.close()

        return True, "Request rejected."

    @staticmethod
    def update_checkin_checkout(request_id, action_type, timestamp):
        conn = get_connection()
        cursor = conn.cursor()

        if action_type == "checkin":
            cursor.execute(
                """
                UPDATE hardware_requests
                SET time_checkin = ?
                WHERE request_id = ?
                """,
                (timestamp, request_id)
            )
        elif action_type == "checkout":
            cursor.execute(
                """
                UPDATE hardware_requests
                SET time_checkout = ?
                WHERE request_id = ?
                """,
                (timestamp, request_id)
            )

        conn.commit()
        conn.close()

        return True, f"Successfully recorded {action_type} at {timestamp}"

    @staticmethod
    def change_available_qty(item_name, category, amount):
        """
        Change shared available quantity.

        amount < 0 = borrow/claim
        amount > 0 = return
        """
        try:
            amount = int(amount)
        except (ValueError, TypeError):
            return False, "Quantity must be a valid whole number."

        if amount == 0:
            return True, "No quantity change was required."

        conn = get_connection()
        cursor = conn.cursor()

        row = InventoryController._find_hardware(
            cursor,
            item_name,
            category
        )

        if not row:
            conn.close()
            return False, f"Hardware item '{item_name}' was not found."

        item_id = row[0]
        current_qty = int(row[3])
        max_qty = InventoryController.get_max_qty(row[2])
        new_qty = current_qty + amount

        if new_qty < 0:
            conn.close()
            return (
                False,
                f"Only {current_qty} unit(s) of {item_name} are available."
            )

        if new_qty > max_qty:
            conn.close()
            return (
                False,
                f"Available quantity cannot exceed the maximum of "
                f"{max_qty} for {row[2]}."
            )

        status = compute_status(new_qty)

        cursor.execute(
            """
            UPDATE hardware
            SET quantity = ?, status = ?
            WHERE item_id = ?
            """,
            (new_qty, status, item_id)
        )

        conn.commit()
        conn.close()

        log_info(
            f"Inventory Quantity Updated: '{item_name}' changed "
            f"from {current_qty} to {new_qty}."
        )

        return True, f"Available quantity is now {new_qty}."

    @staticmethod
    def process_borrow_return(
        item_name,
        category,
        request_id,
        action_name,
        username
    ):
        """
        Process an actual claim/return and update the shared inventory.
        """
        import json
        import os

        if action_name not in ("claim item", "return item"):
            return False, "Invalid transaction action."

        if not request_id or str(request_id) == "0":
            return False, "This hardware item has no request record."

        if not os.path.exists("hardware_requests.json"):
            return False, "No request record was found."

        try:
            with open(
                "hardware_requests.json",
                "r",
                encoding="utf-8"
            ) as f:
                requests = json.load(f)
        except Exception:
            return False, "Unable to read the request records."

        selected = None

        for req in requests:
            if str(req.get("req_id")) == str(request_id):
                selected = req
                break

        if not selected:
            return False, "The selected request could not be found."

        # A user can only process their own request.
        if selected.get("username") != username:
            return False, "You can only claim or return your own request."

        request_status = selected.get("status", "Pending")
        borrow_status = selected.get(
            "borrow_status",
            "Not Borrowed"
        )

        if request_status != "Approved":
            return (
                False,
                "The request must be approved by the Admin before the item can be claimed."
            )

        try:
            requested_qty = int(selected.get("qty", 0))
        except (ValueError, TypeError):
            return False, "Invalid requested quantity."

        if requested_qty <= 0:
            return False, "Requested quantity must be greater than zero."

        timestamp = __import__("datetime").datetime.now().strftime(
            "%Y-%m-%d %H:%M"
        )

        if action_name == "claim item":
            if borrow_status == "Borrowed":
                return False, "This request has already been claimed."

            success, msg = InventoryController.change_available_qty(
                item_name,
                category,
                -requested_qty
            )

            if not success:
                return False, msg

            selected["borrow_status"] = "Borrowed"
            selected["time_checkin"] = timestamp

        else:
            if borrow_status != "Borrowed":
                return False, "This request is not currently borrowed."

            success, msg = InventoryController.change_available_qty(
                item_name,
                category,
                requested_qty
            )

            if not success:
                return False, msg

            selected["borrow_status"] = "Returned"
            selected["time_checkout"] = timestamp

        try:
            with open(
                "hardware_requests.json",
                "w",
                encoding="utf-8"
            ) as f:
                json.dump(
                    requests,
                    f,
                    indent=4
                )
        except Exception as e:
            # If the JSON cannot be saved, reverse the inventory change.
            reverse_amount = (
                requested_qty
                if action_name == "claim item"
                else -requested_qty
            )

            InventoryController.change_available_qty(
                item_name,
                category,
                reverse_amount
            )

            return False, f"Unable to save transaction record: {e}"

        log_info(
            f"{action_name.capitalize()} completed for '{item_name}' "
            f"by user '{username}'."
        )

        return True, f"{action_name.capitalize()} completed successfully."


# ============================================================
# MERGED FROM: LAB ACT 6=midterms/views/inventory_view.py
# ============================================================
# views/inventory_view.py

import tkinter as tk
from tkinter import messagebox, ttk
import datetime
import json
import os

REQUESTS_FILE = "hardware_requests.json"

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


def load_persistent_requests():
    if os.path.exists(REQUESTS_FILE):
        try:
            with open(REQUESTS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_persistent_requests(requests_list):
    try:
        with open(REQUESTS_FILE, "w") as f:
            json.dump(requests_list, f, indent=4)
    except Exception as e:
        log_info(f"Error saving requests: {e}")


class AdminApprovalTab(tk.Frame):
    def __init__(self, parent, master_app):
        super().__init__(parent, bg=PURPLE["primary"])
        self.master_app = master_app
        self.checked_hw_keys = set()  # Track selected request IDs
        self.hw_request_map = {}  # Treeview row ID -> request ID
        self.select_all_state = False  # Toggle state for Select All

        tk.Label(
            self, 
            text="Pending Hardware & Password Reset Requests", 
            font=("Arial", 11, "bold"), 
            bg=PURPLE["primary"], 
            fg="white"
        ).pack(pady=10)

        # Section 1: Hardware Requests Approval Table
        hw_header_row = tk.Frame(self, bg=PURPLE["primary"])
        hw_header_row.pack(fill=tk.X, padx=15)

        tk.Label(hw_header_row, text="Pending Hardware Requests", font=("Arial", 10, "bold"), bg=PURPLE["primary"], fg=PURPLE["panel2"]).pack(side=tk.LEFT)
        
        # Select All Toggle Button
        self.btn_select_all = tk.Button(
            hw_header_row, 
            text="Select All ☐", 
            command=self.toggle_select_all, 
            bg=PURPLE["dark"], 
            fg="white", 
            font=("Arial", 8, "bold"),
            padx=6, pady=2
        )
        self.btn_select_all.pack(side=tk.RIGHT)

        hw_frame = tk.Frame(self, bg=PURPLE["panel"])
        hw_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=5)

        hw_columns = ("Select", "User", "Date", "Subject", "Item", "Qty", "Status", "_RequestID")
        self.hw_tree = ttk.Treeview(hw_frame, columns=hw_columns, show="headings", height=6, style="Purple.Treeview")
        
        col_widths = [60, 100, 130, 120, 140, 70, 100, 0]
        for col, w in zip(hw_columns, col_widths):
            self.hw_tree.heading(col, text=col)
            self.hw_tree.column(col, width=w, minwidth=0, stretch=False, anchor="center" if col in ["Select", "Qty", "Status"] else "w")

        hw_scrollbar = ttk.Scrollbar(hw_frame, orient=tk.VERTICAL, style="Purple.Vertical.TScrollbar", command=self.hw_tree.yview)
        self.hw_tree.configure(yscrollcommand=hw_scrollbar.set)
        self.hw_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        hw_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.hw_tree.bind("<Button-1>", self.on_hw_tree_click)

        hw_btn_frame = tk.Frame(self, bg=PURPLE["primary"])
        hw_btn_frame.pack(pady=5)

        tk.Button(
            hw_btn_frame, 
            text="Approve Hardware Request", 
            command=lambda: self.process_hardware_request(True), 
            bg="#27ae60", 
            fg="white", 
            font=("Arial", 9, "bold"),
            width=22
        ).pack(side=tk.LEFT, padx=10)
        
        tk.Button(
            hw_btn_frame, 
            text="Reject Hardware Request", 
            command=lambda: self.process_hardware_request(False), 
            bg="#c0392b", 
            fg="white", 
            font=("Arial", 9, "bold"),
            width=22
        ).pack(side=tk.LEFT, padx=10)

        # Section 2: Password Reset Requests Table
        pw_label = tk.Label(self, text="Pending Password Reset Requests", font=("Arial", 10, "bold"), bg=PURPLE["primary"], fg=PURPLE["panel2"])
        pw_label.pack(anchor="w", padx=15, pady=(10, 0))

        tree_frame = tk.Frame(self, bg=PURPLE["panel"])
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=5)

        self.tree = ttk.Treeview(tree_frame, columns=("ID", "Username", "Email"), show="headings", height=5)
        self.tree.heading("ID", text="ID")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Email", text="Registered Email")
        
        self.tree.column("ID", width=60, anchor=tk.CENTER)
        self.tree.column("Username", width=150, anchor=tk.CENTER)
        self.tree.column("Email", width=250, anchor=tk.CENTER)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, style="Purple.Vertical.TScrollbar", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        btn_frame = tk.Frame(self, bg=PURPLE["primary"])
        btn_frame.pack(pady=10)

        tk.Button(
            btn_frame, 
            text="Approve Password Reset", 
            command=lambda: self.process_reset(True), 
            bg="#27ae60", 
            fg="white", 
            font=("Arial", 9, "bold"),
            width=22
        ).pack(side=tk.LEFT, padx=10)
        
        tk.Button(
            btn_frame, 
            text="Reject Password Reset", 
            command=lambda: self.process_reset(False), 
            bg="#c0392b", 
            fg="white", 
            font=("Arial", 9, "bold"),
            width=22
        ).pack(side=tk.LEFT, padx=10)

        self.load_requests()

    def on_hw_tree_click(self, event):
        region = self.hw_tree.identify("region", event.x, event.y)
        if region == "cell":
            column = self.hw_tree.identify_column(event.x)
            if column == "#1":  # Checkbox column lamang
                item_id = self.hw_tree.identify_row(event.y)
                if item_id:
                    values = self.hw_tree.item(item_id, "values")
                    if values and len(values) > 4:
                        request_id = str(values[7]) if len(values) > 7 else str(self.hw_request_map.get(item_id, ""))
                        if not request_id:
                            return
                        key = request_id
                        
                        if key in self.checked_hw_keys:
                            self.checked_hw_keys.remove(key)
                        else:
                            self.checked_hw_keys.add(key)
                        
                        self.refresh_hw_tree_selections()

    def refresh_hw_tree_selections(self):
        all_children = self.hw_tree.get_children()
        if not all_children:
            return

        for child in all_children:
            current_values = list(self.hw_tree.item(child, "values"))
            request_id = str(current_values[7]) if len(current_values) > 7 else str(self.hw_request_map.get(child, ""))
            key = request_id
            
            if key in self.checked_hw_keys:
                current_values[0] = "☑"
            else:
                current_values[0] = "☐"
            self.hw_tree.item(child, values=current_values)

        if len(self.checked_hw_keys) == len(all_children) and len(all_children) > 0:
            self.select_all_state = True
            self.btn_select_all.config(text="Select All ☑")
        else:
            self.select_all_state = False
            self.btn_select_all.config(text="Select All ☐")

    def toggle_select_all(self):
        all_children = self.hw_tree.get_children()
        if not all_children:
            return

        self.select_all_state = not self.select_all_state
        self.checked_hw_keys.clear()

        if self.select_all_state:
            self.btn_select_all.config(text="Select All ☑")
            for child in all_children:
                values = self.hw_tree.item(child, "values")
                request_id = str(values[7]) if len(values) > 7 else str(self.hw_request_map.get(child, ""))
                if request_id:
                    self.checked_hw_keys.add(request_id)
        else:
            self.btn_select_all.config(text="Select All ☐")

        for child in all_children:
            current_values = list(self.hw_tree.item(child, "values"))
            current_values[0] = "☑" if self.select_all_state else "☐"
            self.hw_tree.item(child, values=current_values)

    def load_requests(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for r in AuthController.fetch_pending_resets():
            self.tree.insert("", tk.END, values=r)

        for row in self.hw_tree.get_children():
            self.hw_tree.delete(row)
        self.hw_request_map.clear()
        
        all_requests = load_persistent_requests()
        for req in all_requests:
            if req.get("status") == "Pending":
                username = str(req["username"])
                date_str = str(req["date"])
                item_name = str(req["item"])
                request_id = str(req.get("req_id", ""))
                checkbox_state = "☑" if request_id in self.checked_hw_keys else "☐"
                row_iid = self.hw_tree.insert("", tk.END, values=(
                    checkbox_state,
                    username,
                    date_str,
                    req.get("subject", ""),
                    item_name,
                    req.get("qty", ""),
                    req.get("status", "Pending"),
                    request_id
                ))
                self.hw_request_map[row_iid] = request_id
        
        if self.hw_tree.get_children():
            self.refresh_hw_tree_selections()

    def process_hardware_request(self, approve):
        if not self.checked_hw_keys:
            messagebox.showerror("Error", "Please select at least one hardware request using the checkboxes.")
            return
        
        new_status = "Approved" if approve else "Rejected"
        all_requests = load_persistent_requests()
        
        for req in all_requests:
            request_id = str(req.get("req_id", ""))
            if request_id in self.checked_hw_keys:
                req["status"] = new_status

        save_persistent_requests(all_requests)
        messagebox.showinfo("Success", f"Selected hardware request(s) {new_status.lower()} successfully!")
        
        self.checked_hw_keys.clear()
        self.select_all_state = False
        self.btn_select_all.config(text="Select All ☐")
        self.load_requests()

    def process_reset(self, approve):
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showerror("Error", "Please select a password reset request.")
            return
        
        for item in selected_items:
            values = self.tree.item(item, "values")
            user_id = values[0]
            
            success, msg = AuthController.handle_reset_approval(user_id, approve)
            if not success:
                messagebox.showerror("Error", msg)
                return
        
        status_text = "approved" if approve else "rejected"
        messagebox.showinfo("Success", f"Password reset request {status_text} successfully.")
        self.load_requests()



class UserRequestFormTab(tk.Frame):
    def __init__(self, parent, username, master_app):
        super().__init__(parent, bg=PURPLE["primary"])
        self.username = username
        self.master_app = master_app

        tk.Label(
            self,
            text="Hardware Request Form",
            font=("Arial", 12, "bold"),
            bg=PURPLE["primary"],
            fg="white"
        ).pack(pady=10)

        form_frame = tk.LabelFrame(
            self,
            text=" Fill out Request Details ",
            font=("Arial", 10, "bold"),
            bg=PURPLE["panel"],
            padx=15,
            pady=15
        )
        form_frame.pack(padx=20, pady=5, fill=tk.BOTH, expand=True)

        fields = [
            ("Full Name:", "name_entry"),
            ("Student ID:", "id_entry"),
            ("Professor:", "prof_entry"),
            ("Subject:", "subject_entry"),
            ("Schedule:", "sched_entry")
        ]

        self.entries = {}
        for idx, (label_text, attr_name) in enumerate(fields):
            tk.Label(
                form_frame,
                text=label_text,
                bg=PURPLE["panel"],
                font=("Arial", 9, "bold"),
                anchor="w"
            ).grid(row=idx, column=0, sticky="w", pady=4, padx=5)

            entry = tk.Entry(form_frame, width=32, font=("Arial", 9))
            entry.grid(row=idx, column=1, columnspan=2, pady=4, padx=5, sticky="w")
            self.entries[attr_name] = entry

        hw_header_frame = tk.Frame(form_frame, bg=PURPLE["panel"])
        hw_header_frame.grid(row=5, column=0, columnspan=3, sticky="we", pady=(10, 2))

        tk.Label(
            hw_header_frame,
            text="Hardware Items:",
            bg=PURPLE["panel"],
            font=("Arial", 9, "bold")
        ).pack(side=tk.LEFT)

        btn_add_item = tk.Button(
            hw_header_frame,
            text="+ Add Hardware Item",
            command=self.add_hardware_row,
            bg="#27ae60",
            fg="white",
            font=("Arial", 8, "bold"),
            padx=6, pady=2
        )
        btn_add_item.pack(side=tk.RIGHT)

        self.items_container = tk.Frame(form_frame, bg=PURPLE["panel"])
        self.items_container.grid(row=6, column=0, columnspan=3, sticky="we", pady=2)

        self.max_qty_label = tk.Label(
            form_frame,
            text="Max Available Qty is automatically determined by the selected category.",
            bg=PURPLE["panel"],
            fg="#777777",
            font=("Arial", 8, "italic")
        )
        self.max_qty_label.grid(row=7, column=0, columnspan=3, pady=(5, 0))

        self.hardware_rows = []
        self.add_hardware_row()

        btn_submit = tk.Button(
            form_frame,
            text="Submit Hardware Request",
            command=self.submit_request,
            bg=PURPLE["accent_dark"],
            fg="white",
            font=("Arial", 9, "bold"),
            padx=12,
            pady=6
        )
        btn_submit.grid(row=8, column=0, columnspan=3, pady=15)

    def add_hardware_row(self):
        row_frame = tk.Frame(self.items_container, bg=PURPLE["panel"], pady=3)
        row_frame.pack(fill=tk.X, expand=True)

        tk.Label(
            row_frame,
            text="Hardware Item:",
            bg=PURPLE["panel"],
            font=("Arial", 9)
        ).pack(side=tk.LEFT, padx=(0, 4))

        item_entry = tk.Entry(row_frame, width=18, font=("Arial", 9))
        item_entry.pack(side=tk.LEFT, padx=(0, 8))

        tk.Label(
            row_frame,
            text="Category:",
            bg=PURPLE["panel"],
            font=("Arial", 9)
        ).pack(side=tk.LEFT, padx=(0, 4))

        category_cb = ttk.Combobox(
            row_frame,
            values=InventoryController.CATEGORIES,
            state="readonly",
            width=17,
            font=("Arial", 9)
        )
        category_cb.set("Microcontroller")
        category_cb.pack(side=tk.LEFT, padx=(0, 8))

        tk.Label(
            row_frame,
            text="Requested Qty:",
            bg=PURPLE["panel"],
            font=("Arial", 9)
        ).pack(side=tk.LEFT, padx=(0, 4))

        qty_entry = tk.Entry(row_frame, width=8, font=("Arial", 9))
        qty_entry.pack(side=tk.LEFT, padx=(0, 8))

        del_btn = tk.Button(
            row_frame,
            text="X",
            command=lambda rf=row_frame, tup=(item_entry, category_cb, qty_entry):
                self.remove_hardware_row(rf, tup),
            bg="#c0392b",
            fg="white",
            font=("Arial", 8, "bold"),
            width=2
        )
        del_btn.pack(side=tk.LEFT)

        category_cb.bind(
            "<<ComboboxSelected>>",
            lambda e, cb=category_cb: self.update_max_qty_hint(cb)
        )

        self.hardware_rows.append((item_entry, category_cb, qty_entry, row_frame))

    def update_max_qty_hint(self, category_cb):
        category = category_cb.get()
        max_qty = InventoryController.get_max_qty(category)
        self.max_qty_label.config(
            text=f"Max Available Qty is automatically determined by the selected category.  Max: {max_qty}"
        )

    def remove_hardware_row(self, row_frame, tup):
        if len(self.hardware_rows) <= 1:
            messagebox.showerror("Error", "You must keep at least one hardware item row.")
            return

        row_frame.destroy()
        self.hardware_rows = [r for r in self.hardware_rows if r[3] != row_frame]

    def submit_request(self):
        name = self.entries["name_entry"].get().strip()
        student_id = self.entries["id_entry"].get().strip()
        prof = self.entries["prof_entry"].get().strip()
        subject = self.entries["subject_entry"].get().strip()
        sched = self.entries["sched_entry"].get().strip()

        if not name or not student_id or not prof or not subject or not sched:
            messagebox.showerror("Validation Error", "Please fill out all student details.")
            return

        items_data = []

        for item_entry, category_cb, qty_entry, _ in self.hardware_rows:
            i_name = item_entry.get().strip()
            category = category_cb.get().strip()
            i_qty = qty_entry.get().strip()

            if not i_name or not category or not i_qty:
                messagebox.showerror(
                    "Validation Error",
                    "All hardware item, category, and quantity fields must be filled out."
                )
                return

            try:
                requested_qty = int(i_qty)
                if requested_qty <= 0:
                    raise ValueError
            except ValueError:
                messagebox.showerror(
                    "Validation Error",
                    "Requested Qty must be a positive whole number."
                )
                return

            max_qty = InventoryController.get_max_qty(category)
            if requested_qty > max_qty:
                messagebox.showerror(
                    "Quantity Error",
                    f"{i_name} cannot exceed the maximum quantity of {max_qty} for {category}."
                )
                return

            # Make sure the item exists in the shared inventory.
            # A new item starts with its category's fixed maximum quantity.
            success, msg = InventoryController.ensure_item(i_name, category)
            if not success:
                messagebox.showerror("Inventory Error", msg)
                return

            available_qty = InventoryController.get_available_qty(i_name, category)

            if requested_qty > available_qty:
                messagebox.showerror(
                    "Insufficient Available Quantity",
                    f"Only {available_qty} unit(s) of {i_name} are currently available."
                )
                return

            items_data.append((i_name, category, str(requested_qty), available_qty))

        current_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

        all_requests = load_persistent_requests()
        new_requests = []

        for item_index, (i_name, category, i_qty, item_available_qty) in enumerate(items_data):
            # Add the item index so every hardware row in one submission
            # receives its own unique request ID.
            req_id = (
                int(datetime.datetime.now().timestamp() * 1000)
                + len(all_requests)
                + item_index
            )

            req_dict = {
                "req_id": str(req_id),
                "username": self.username,
                "date": current_date,
                "subject": subject,
                "item": i_name,
                "category": category,
                "max_qty": InventoryController.get_max_qty(category),
                "qty": i_qty,
                "status": "Pending",
                "borrow_status": "Not Borrowed"
            }

            new_requests.append(req_dict)

            self.master_app.add_request_status_item(
                str(req_id),
                current_date,
                subject,
                i_name,
                category,
                req_dict["max_qty"],
                item_available_qty,
                i_qty,
                "Pending",
                "Not Borrowed"
            )

        all_requests.extend(new_requests)
        save_persistent_requests(all_requests)

        messagebox.showinfo(
            "Success",
            f"Hardware request successfully submitted with {len(items_data)} item(s)!"
        )

        for entry in self.entries.values():
            entry.delete(0, tk.END)

        for _, _, _, row_frame in self.hardware_rows[1:]:
            row_frame.destroy()

        self.hardware_rows = self.hardware_rows[:1]
        self.hardware_rows[0][0].delete(0, tk.END)
        self.hardware_rows[0][2].delete(0, tk.END)
        self.hardware_rows[0][1].set("Microcontroller")
        self.update_max_qty_hint(self.hardware_rows[0][1])

class UserRequestStatusTab(tk.Frame):
    def __init__(self, parent, username):
        super().__init__(parent, bg=PURPLE["primary"])
        self.username = username
        self.checked_status_items = set()

        tk.Label(
            self,
            text="My Request Status History",
            font=("Arial", 12, "bold"),
            bg=PURPLE["primary"],
            fg="white"
        ).pack(pady=10)

        status_frame = tk.Frame(self, bg=PURPLE["panel"])
        status_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        columns = (
            "Select",
            "Date",
            "Subject",
            "Item",
            "Category",
            "Max Qty Available",
            "Available Qty Item",
            "Requested Qty",
            "Request Status",
            "Borrowed or Returned Status"
        )

        self.status_tree = ttk.Treeview(
            status_frame,
            columns=columns,
            show="headings",
            style="Purple.Treeview",
            height=12
        )

        col_widths = [55, 125, 105, 120, 135, 125, 120, 100, 115, 155]

        for col, w in zip(columns, col_widths):
            self.status_tree.heading(col, text=col)
            self.status_tree.column(
                col,
                width=w,
                anchor="center" if col in [
                    "Select",
                    "Date",
                    "Max Qty Available",
                    "Available Qty Item",
                    "Requested Qty",
                    "Request Status",
                    "Borrowed or Returned Status"
                ] else "w"
            )

        self.status_tree.tag_configure("pending", background=PURPLE["panel2"])
        self.status_tree.tag_configure("approved", background="#d1fae5")
        self.status_tree.tag_configure("rejected", background="#f9d5d5")

        scrollbar = ttk.Scrollbar(
            status_frame,
            orient=tk.VERTICAL,
            command=self.status_tree.yview
        )
        h_scrollbar = ttk.Scrollbar(
            status_frame,
            orient=tk.HORIZONTAL,
            command=self.status_tree.xview
        )
        self.status_tree.configure(
            yscrollcommand=scrollbar.set,
            xscrollcommand=h_scrollbar.set
        )

        self.status_tree.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(
            side=tk.BOTTOM,
            fill=tk.X
        )

        self.status_tree.bind("<Button-1>", self.on_tree_click)

    def on_tree_click(self, event):
        region = self.status_tree.identify("region", event.x, event.y)

        if region == "cell":
            column = self.status_tree.identify_column(event.x)

            if column == "#1":
                item_id = self.status_tree.identify_row(event.y)

                if item_id:
                    # Use the Treeview row ID for selection.
                    # Request IDs are not guaranteed to be unique when one
                    # submission contains several hardware items.
                    if item_id in self.checked_status_items:
                        self.checked_status_items.remove(item_id)
                    else:
                        self.checked_status_items.add(item_id)

                    self.refresh_treeview_selections()

    def refresh_treeview_selections(self):
        for child in self.status_tree.get_children():
            current_values = list(self.status_tree.item(child, "values"))
            current_values[0] = "☑" if child in self.checked_status_items else "☐"
            self.status_tree.item(child, values=current_values)

    def clear_rows(self):
        for child in self.status_tree.get_children():
            self.status_tree.delete(child)
        self.checked_status_items.clear()

    def add_row(
        self,
        req_id,
        date_val,
        subject_val,
        item_val,
        category_val,
        max_qty,
        available_qty,
        requested_qty,
        status_val,
        borrow_status
    ):
        tag = (
            "approved" if status_val == "Approved"
            else "rejected" if status_val == "Rejected"
            else "pending"
        )

        # A newly inserted row starts unchecked. The actual Treeview row ID
        # is used for checkbox selection, so duplicate request IDs are safe.
        checkbox_state = "☐"

        # The first tag is the color tag; the second stores the internal request ID.
        self.status_tree.insert(
            "",
            0,
            values=(
                checkbox_state,
                date_val,
                subject_val,
                item_val,
                category_val,
                max_qty,
                available_qty,
                requested_qty,
                status_val,
                borrow_status
            ),
            tags=(tag, str(req_id))
        )

    def load_requests(self):
        self.clear_rows()

        all_requests = load_persistent_requests()

        for req in reversed(all_requests):
            if req.get("username") != self.username:
                continue

            category = req.get("category", "Others")
            max_qty = InventoryController.get_max_qty(category)
            available_qty = InventoryController.get_available_qty(
                req.get("item", ""),
                category
            )

            self.add_row(
                req.get("req_id", ""),
                req.get("date", ""),
                req.get("subject", ""),
                req.get("item", ""),
                category,
                max_qty,
                available_qty,
                req.get("qty", ""),
                req.get("status", "Pending"),
                req.get("borrow_status", "Not Borrowed")
            )
class UserProfileTab(tk.Frame):
    def __init__(self, parent, username):
        super().__init__(parent, bg=PURPLE["primary"])
        self.username = username

        tk.Label(
            self, 
            text="My Profile & Security Management", 
            font=("Arial", 12, "bold"), 
            bg=PURPLE["primary"], 
            fg="white"
        ).pack(pady=15)

        form_frame = tk.LabelFrame(self, text=" Change Password ", font=("Arial", 10, "bold"), bg=PURPLE["panel"], padx=15, pady=15)
        form_frame.pack(padx=20, pady=10, fill=tk.X)

        tk.Label(form_frame, text="Current Password:", bg=PURPLE["panel"], fg=PURPLE["text"], font=("Arial", 9)).grid(row=0, column=0, sticky="w", pady=5)
        self.curr_pass_entry = tk.Entry(form_frame, show="*", width=25, font=("Arial", 9))
        self.curr_pass_entry.grid(row=0, column=1, pady=5, padx=5)

        tk.Label(form_frame, text="New Password:", bg=PURPLE["panel"], fg=PURPLE["text"], font=("Arial", 9)).grid(row=1, column=0, sticky="w", pady=5)
        self.new_pass_entry = tk.Entry(form_frame, show="*", width=25, font=("Arial", 9))
        self.new_pass_entry.grid(row=1, column=1, pady=5, padx=5)

        tk.Label(form_frame, text="Confirm New Password:", bg=PURPLE["panel"], fg=PURPLE["text"], font=("Arial", 9)).grid(row=2, column=0, sticky="w", pady=5)
        self.conf_pass_entry = tk.Entry(form_frame, show="*", width=25, font=("Arial", 9))
        self.conf_pass_entry.grid(row=2, column=1, pady=5, padx=5)

        self.show_pass_var = tk.IntVar(value=0)
        self.show_pass_chk = tk.Checkbutton(
            form_frame, 
            text="Show Passwords", 
            variable=self.show_pass_var, 
            command=self.toggle_pass_visibility, 
            font=("Arial", 8), 
            bg=PURPLE["panel"], 
            selectcolor="#fff"
        )
        self.show_pass_chk.grid(row=3, column=1, sticky="w", pady=2, padx=5)

        tk.Button(
            form_frame, 
            text="Update Password", 
            command=self.change_password, 
            bg=PURPLE["accent_dark"], 
            fg="white", 
            font=("Arial", 9, "bold"),
            width=18
        ).grid(row=4, column=1, sticky="e", pady=10)

    def toggle_pass_visibility(self):
        show_char = "" if self.show_pass_var.get() == 1 else "*"
        self.curr_pass_entry.config(show=show_char)
        self.new_pass_entry.config(show=show_char)
        self.conf_pass_entry.config(show=show_char)

    def change_password(self):
        curr = self.curr_pass_entry.get().strip()
        new_p = self.new_pass_entry.get().strip()
        conf = self.conf_pass_entry.get().strip()

        if not curr or not new_p or not conf:
            messagebox.showerror("Error", "All fields are required.")
            return

        if new_p != conf:
            messagebox.showerror("Error", "New passwords do not match.")
            return

        success, msg = AuthController.update_password_direct(self.username, curr, new_p)
        if success:
            messagebox.showinfo("Success", msg)
            self.curr_pass_entry.delete(0, tk.END)
            self.new_pass_entry.delete(0, tk.END)
            self.conf_pass_entry.delete(0, tk.END)
            self.show_pass_var.set(0)
            self.toggle_pass_visibility()
        else:
            messagebox.showerror("Error", msg)



class InventoryApp:
    def __init__(self, root, role="user", username="cj"):
        self.root = root
        self.role = role.lower()
        self.username = username

        panel_title = (
            "Campus Hardware Inventory System (ADMIN PANEL)"
            if self.role == "admin"
            else "Campus Hardware Inventory System (USER PANEL)"
        )

        self.root.title(panel_title)
        self.root.geometry("860x740")
        self.root.config(bg=PURPLE["primary"])
        self.center_window(860, 740)

        # Consistent purple styling for ttk widgets.
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Purple.TNotebook",
            background=PURPLE["primary"],
            borderwidth=0
        )
        style.configure(
            "Purple.TNotebook.Tab",
            background=PURPLE["panel"],
            foreground=PURPLE["text"],
            padding=(12, 6),
            font=("Arial", 9)
        )
        style.map(
            "Purple.TNotebook.Tab",
            background=[("selected", PURPLE["primary2"])],
            foreground=[("selected", PURPLE["white"])]
        )

        style.configure(
            "Purple.Treeview",
            background=PURPLE["panel2"],
            fieldbackground=PURPLE["panel2"],
            foreground=PURPLE["text"],
            rowheight=26,
            font=("Arial", 9),
            borderwidth=0
        )
        style.configure(
            "Purple.Treeview.Heading",
            background=PURPLE["dark"],
            foreground=PURPLE["white"],
            font=("Arial", 9, "bold"),
            relief="flat",
            padding=(5, 5)
        )
        style.map(
            "Purple.Treeview",
            background=[("selected", PURPLE["accent"])],
            foreground=[("selected", PURPLE["white"])]
        )

        style.configure(
            "Purple.Vertical.TScrollbar",
            background=PURPLE["primary2"],
            troughcolor=PURPLE["panel"],
            bordercolor=PURPLE["border"],
            arrowcolor=PURPLE["white"]
        )

        style.configure(
            "Purple.TCombobox",
            fieldbackground=PURPLE["panel2"],
            background=PURPLE["panel"],
            foreground=PURPLE["text"]
        )

        self.checked_items = set()
        self.select_all_catalog_state = False
        self.catalog_row_data = {}

        top_header = tk.Frame(root, bg=PURPLE["deep"], padx=10, pady=8)
        top_header.pack(fill=tk.X)

        user_info_lbl = tk.Label(
            top_header,
            text=f"Logged in as: {self.username} [{self.role.upper()}]",
            font=("Arial", 10, "bold"),
            bg=PURPLE["deep"],
            fg="white"
        )
        user_info_lbl.pack(side=tk.LEFT)

        logout_btn = tk.Button(
            top_header,
            text="Logout",
            command=self.logout,
            bg="#c0392b",
            fg="white",
            font=("Arial", 9, "bold"),
            relief="flat",
            padx=8
        )
        logout_btn.pack(side=tk.RIGHT)

        self.notebook = ttk.Notebook(root, style="Purple.TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        if self.role == "admin":
            self.catalog_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.catalog_frame, text="Hardware Catalog")
            self.build_catalog_tab(self.catalog_frame)

            self.approvals_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.approvals_frame, text="Admin Approvals")
            self.admin_approval_tab = AdminApprovalTab(
                self.approvals_frame,
                self
            )
            self.admin_approval_tab.pack(fill=tk.BOTH, expand=True)
        else:
            self.request_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.request_frame, text="Request Form")
            self.user_request_tab = UserRequestFormTab(
                self.request_frame,
                self.username,
                self
            )
            self.user_request_tab.pack(fill=tk.BOTH, expand=True)

            self.status_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.status_frame, text="Request Status")
            self.user_status_tab = UserRequestStatusTab(
                self.status_frame,
                self.username
            )
            self.user_status_tab.pack(fill=tk.BOTH, expand=True)

            self.load_user_history()

            self.catalog_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.catalog_frame, text="Hardware Catalog")
            self.build_catalog_tab(self.catalog_frame)

            self.profile_frame = ttk.Frame(self.notebook)
            self.notebook.add(
                self.profile_frame,
                text="My Profile & Security"
            )
            self.user_profile_tab = UserProfileTab(
                self.profile_frame,
                self.username
            )
            self.user_profile_tab.pack(fill=tk.BOTH, expand=True)

        # Keep every opened catalog/status view synchronized with the shared database.
        self.auto_refresh_inventory()

    def center_window(self, width, height):
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = int((screen_width / 2) - (width / 2))
        y = int((screen_height / 2) - (height / 2))
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def logout(self):
        self.root.destroy()

    def add_request_status_item(
        self,
        req_id,
        date_val,
        subject_val,
        item_val,
        category_val,
        max_qty,
        available_qty,
        qty_val,
        status_val,
        borrow_status
    ):
        if hasattr(self, "user_status_tab"):
            self.user_status_tab.add_row(
                req_id,
                date_val,
                subject_val,
                item_val,
                category_val,
                max_qty,
                available_qty,
                qty_val,
                status_val,
                borrow_status
            )

    def load_user_history(self):
        if not hasattr(self, "user_status_tab"):
            return

        self.user_status_tab.clear_rows()

        all_requests = load_persistent_requests()

        for req in reversed(all_requests):
            if req.get("username") != self.username:
                continue

            category = req.get("category", "Others")
            max_qty = InventoryController.get_max_qty(category)
            available_qty = InventoryController.get_available_qty(
                req.get("item", ""),
                category
            )

            self.user_status_tab.add_row(
                req.get("req_id", ""),
                req.get("date", ""),
                req.get("subject", ""),
                req.get("item", ""),
                category,
                max_qty,
                available_qty,
                req.get("qty", ""),
                req.get("status", "Pending"),
                req.get("borrow_status", "Not Borrowed")
            )

    def build_catalog_tab(self, parent):
        main_tab_frame = tk.Frame(parent, bg=PURPLE["primary"])
        main_tab_frame.pack(
            fill=tk.BOTH,
            expand=True,
            padx=10,
            pady=10
        )

        filter_frame = tk.Frame(main_tab_frame, bg=PURPLE["primary"])
        filter_frame.pack(fill=tk.X, pady=5)

        tk.Label(
            filter_frame,
            text="Search:",
            bg=PURPLE["primary"],
            fg="white",
            font=("Arial", 9, "bold")
        ).pack(side=tk.LEFT, padx=(0, 5))

        self.search_entry = tk.Entry(
            filter_frame,
            font=("Arial", 9),
            width=18
        )
        self.search_entry.pack(side=tk.LEFT, padx=(0, 15))
        self.search_entry.bind(
            "<KeyRelease>",
            lambda e: self.load_inventory()
        )

        tk.Label(
            filter_frame,
            text="Filter Category:",
            bg=PURPLE["primary"],
            fg="white",
            font=("Arial", 9, "bold")
        ).pack(side=tk.LEFT, padx=(0, 5))

        self.category_cb = ttk.Combobox(
            filter_frame,
            style="Purple.TCombobox",
            values=["All"] + InventoryController.CATEGORIES,
            state="readonly",
            width=17
        )
        self.category_cb.set("All")
        self.category_cb.pack(side=tk.LEFT)
        self.category_cb.bind(
            "<<ComboboxSelected>>",
            lambda e: self.load_inventory()
        )

        action_btn_frame = tk.Frame(main_tab_frame, bg=PURPLE["primary"])
        action_btn_frame.pack(fill=tk.X, pady=8)

        export_btn = tk.Button(
            action_btn_frame,
            text="Export Inventory to CSV Report",
            command=self.export_csv,
            bg=PURPLE["muted"],
            fg="white",
            font=("Arial", 9, "bold"),
            padx=8, pady=4
        )
        export_btn.pack(side=tk.LEFT)

        history_btn = tk.Button(
            action_btn_frame,
            text="History (Requests, Borrowed, Returned)",
            command=self.open_history_window,
            bg=PURPLE["primary2"],
            fg="white",
            font=("Arial", 9, "bold"),
            padx=8, pady=4
        )
        history_btn.pack(side=tk.LEFT, padx=(10, 0))

        cat_header_row = tk.Frame(main_tab_frame, bg=PURPLE["primary"])
        cat_header_row.pack(fill=tk.X, padx=2, pady=(5, 2))

        tk.Label(
            cat_header_row,
            text="Hardware Inventory Items",
            font=("Arial", 10, "bold"),
            bg=PURPLE["primary"],
            fg=PURPLE["panel2"]
        ).pack(side=tk.LEFT)

        self.btn_cat_select_all = tk.Button(
            cat_header_row,
            text="Select All ☐",
            command=self.toggle_catalog_select_all,
            bg=PURPLE["dark"],
            fg="white",
            font=("Arial", 8, "bold"),
            padx=6, pady=2
        )
        self.btn_cat_select_all.pack(side=tk.RIGHT)

        tree_frame = tk.Frame(main_tab_frame, bg=PURPLE["panel"])
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        columns = (
            "Select",
            "Date",
            "Subject",
            "Item",
            "Category",
            "Max Qty Available",
            "Available Qty Item",
            "Requested Qty",
            "Request Status",
            "Borrowed or Returned Status"
        )

        self.tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            style="Purple.Treeview",
            height=6
        )

        col_widths = [
            55, 125, 105, 120, 135,
            125, 120, 100, 115, 155
        ]

        for col, w in zip(columns, col_widths):
            self.tree.heading(col, text=col)
            self.tree.column(
                col,
                width=w,
                anchor="center" if col in [
                    "Select",
                    "Date",
                    "Max Qty Available",
                    "Available Qty Item",
                    "Requested Qty",
                    "Request Status",
                    "Borrowed or Returned Status"
                ] else "w"
            )

        self.tree.tag_configure(
            "red",
            background="#f9d5d5"
        )
        self.tree.tag_configure(
            "yellow",
            background=PURPLE["panel2"]
        )
        self.tree.tag_configure(
            "green",
            background="#d1fae5"
        )

        scrollbar = ttk.Scrollbar(
            tree_frame,
            orient=tk.VERTICAL,
            command=self.tree.yview
        )
        h_scrollbar = ttk.Scrollbar(
            tree_frame,
            orient=tk.HORIZONTAL,
            command=self.tree.xview
        )
        self.tree.configure(
            yscrollcommand=scrollbar.set,
            xscrollcommand=h_scrollbar.set
        )

        self.tree.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(
            side=tk.BOTTOM,
            fill=tk.X
        )

        self.tree.bind("<Button-1>", self.on_tree_click)

        update_frame = tk.LabelFrame(
            main_tab_frame,
            text=" Update Checked Record (Qty) ",
            font=("Arial", 10, "bold"),
            padx=10,
            pady=10,
            bg=PURPLE["panel"]
        )
        update_frame.pack(fill=tk.X, pady=8)

        tk.Label(
            update_frame,
            text="New Quantity:",
            font=("Arial", 9),
            bg=PURPLE["panel"]
        ).pack(side=tk.LEFT, padx=(5, 5))

        self.new_qty_entry = tk.Entry(
            update_frame,
            font=("Arial", 9),
            width=12
        )
        self.new_qty_entry.pack(side=tk.LEFT, padx=(0, 20))

        update_btn = tk.Button(
            update_frame,
            text="Update Hardware",
            command=self.update_checked_item,
            bg=PURPLE["accent_dark"],
            fg="white",
            font=("Arial", 9, "bold"),
            padx=10, pady=2
        )
        update_btn.pack(side=tk.LEFT)

        delete_btn = tk.Button(
            main_tab_frame,
            text="Delete Checked Records",
            command=self.delete_checked_items,
            bg="#e74c3c",
            fg="white",
            font=("Arial", 10, "bold"),
            pady=6
        )
        delete_btn.pack(fill=tk.X, pady=(5, 8))

        bottom_action_frame = tk.Frame(
            main_tab_frame,
            bg=PURPLE["primary"]
        )
        bottom_action_frame.pack(fill=tk.X, pady=5)

        self.btn_checkin = tk.Button(
            bottom_action_frame,
            text="Borrow Item",
            command=self.time_checkin,
            bg=PURPLE["primary2"],
            fg="white",
            font=("Arial", 10, "bold"),
            padx=12, pady=6
        )
        self.btn_checkin.pack(side=tk.LEFT, padx=(0, 10))

        self.btn_checkout = tk.Button(
            bottom_action_frame,
            text="Return Item",
            command=self.time_checkout,
            bg=PURPLE["accent_dark"],
            fg="white",
            font=("Arial", 10, "bold"),
            padx=12, pady=6
        )
        self.btn_checkout.pack(side=tk.LEFT)

        self.load_inventory()

    def get_request_for_item(self, item_name):
        all_requests = load_persistent_requests()

        matching = [
            req for req in all_requests
            if str(req.get("item", "")).strip().lower()
            == str(item_name).strip().lower()
        ]

        if self.role != "admin":
            user_matching = [
                req for req in matching
                if req.get("username") == self.username
            ]
            if user_matching:
                matching = user_matching

        if not matching:
            return None

        return matching[-1]

    def on_tree_click(self, event):
        region = self.tree.identify("region", event.x, event.y)

        if region == "cell":
            column = self.tree.identify_column(event.x)

            if column == "#1":
                item_id = self.tree.identify_row(event.y)

                if item_id:
                    if item_id in self.checked_items:
                        self.checked_items.remove(item_id)
                    else:
                        self.checked_items.add(item_id)

                    self.refresh_treeview_selections()

    def refresh_treeview_selections(self):
        all_children = self.tree.get_children()

        if not all_children:
            self.select_all_catalog_state = False
            self.btn_cat_select_all.config(text="Select All ☐")
            return

        for child in all_children:
            current_values = list(
                self.tree.item(child, "values")
            )

            current_values[0] = (
                "☑" if child in self.checked_items else "☐"
            )

            self.tree.item(
                child,
                values=current_values
            )

        if (
            len(self.checked_items) == len(all_children)
            and len(all_children) > 0
        ):
            self.select_all_catalog_state = True
            self.btn_cat_select_all.config(
                text="Select All ☑"
            )
        else:
            self.select_all_catalog_state = False
            self.btn_cat_select_all.config(
                text="Select All ☐"
            )

    def toggle_catalog_select_all(self):
        all_children = self.tree.get_children()

        if not all_children:
            return

        self.select_all_catalog_state = (
            not self.select_all_catalog_state
        )
        self.checked_items.clear()

        if self.select_all_catalog_state:
            self.btn_cat_select_all.config(
                text="Select All ☑"
            )

            for child in all_children:
                self.checked_items.add(child)
        else:
            self.btn_cat_select_all.config(
                text="Select All ☐"
            )

        for child in all_children:
            current_values = list(
                self.tree.item(child, "values")
            )
            current_values[0] = (
                "☑"
                if self.select_all_catalog_state
                else "☐"
            )
            self.tree.item(
                child,
                values=current_values
            )

    def update_checked_item(self):
        if not self.checked_items:
            messagebox.showerror(
                "Selection Error",
                "Please select a record using the checkbox to update."
            )
            return

        selected_row = next(iter(self.checked_items))
        row_data = self.catalog_row_data.get(selected_row)

        if not row_data:
            messagebox.showerror(
                "Update Error",
                "The selected hardware record could not be found."
            )
            return

        qty_val = self.new_qty_entry.get().strip()

        success, msg = InventoryController.update_item(
            row_data["item_id"],
            qty_val,
            "0.00"
        )

        if success:
            messagebox.showinfo("Success", msg)
            self.new_qty_entry.delete(0, tk.END)
            self.checked_items.clear()
            self.load_inventory()
        else:
            messagebox.showerror("Update Hardware", msg)

    def delete_checked_items(self):
        if not self.checked_items:
            messagebox.showerror(
                "Selection Error",
                "Please check at least one record to delete."
            )
            return

        item_ids = []

        for row_iid in self.checked_items:
            row_data = self.catalog_row_data.get(row_iid)
            if row_data:
                item_ids.append(row_data["item_id"])

        item_ids = list(dict.fromkeys(item_ids))

        if not item_ids:
            messagebox.showerror(
                "Delete Error",
                "No valid hardware records were selected."
            )
            return

        if messagebox.askyesno(
            "Confirm Deletion",
            f"Are you sure you want to delete {len(item_ids)} selected record(s)?"
        ):
            success, msg = InventoryController.delete_items(item_ids)

            if success:
                messagebox.showinfo("Success", msg)
                self.checked_items.clear()
                self.load_inventory()
            else:
                messagebox.showerror("Delete Records", msg)

    def load_inventory(self):
        if not hasattr(self, "tree"):
            return

        for row in self.tree.get_children():
            self.tree.delete(row)

        self.catalog_row_data.clear()

        search_query = (
            self.search_entry.get().strip()
            if hasattr(self, "search_entry")
            else ""
        )

        category_filter = (
            self.category_cb.get()
            if hasattr(self, "category_cb")
            else "All"
        )

        rows, total_val = InventoryController.fetch_inventory(
            search_query,
            category_filter
        )

        for row in rows:
            item_id, item_name, category, max_qty, available_qty, status = row

            request = self.get_request_for_item(item_name)

            if request:
                date_val = request.get("date", "-")
                subject_val = request.get("subject", "-")
                requested_qty = request.get("qty", "-")
                request_status = request.get("status", "Pending")
                borrow_status = request.get(
                    "borrow_status",
                    "Not Borrowed"
                )
                request_id = str(request.get("req_id", "0"))
            else:
                date_val = "-"
                subject_val = "-"
                requested_qty = "-"
                request_status = "-"
                borrow_status = "-"
                request_id = "0"

            row_iid = f"{item_id}_{request_id}"

            tag = (
                "red" if status == "Out of Stock"
                else "yellow" if status == "Low Stock"
                else "green"
            )

            checkbox_state = (
                "☑"
                if row_iid in self.checked_items
                else "☐"
            )

            display_row = (
                checkbox_state,
                date_val,
                subject_val,
                item_name,
                category,
                max_qty,
                available_qty,
                requested_qty,
                request_status,
                borrow_status
            )

            self.catalog_row_data[row_iid] = {
                "item_id": item_id,
                "item_name": item_name,
                "category": category,
                "request_id": request_id,
                "requested_qty": requested_qty,
                "request_status": request_status,
                "borrow_status": borrow_status
            }

            self.tree.insert(
                "",
                tk.END,
                iid=row_iid,
                values=display_row,
                tags=(tag,)
            )

        # Remove checked IDs for rows that no longer exist.
        current_ids = set(self.tree.get_children())
        self.checked_items.intersection_update(current_ids)

        if hasattr(self, "btn_cat_select_all"):
            self.refresh_treeview_selections()

    def export_csv(self):
        # Keep the original export button working.
        success, msg = InventoryController.export_csv_report()

        if success:
            messagebox.showinfo("Success", msg)
        else:
            messagebox.showerror("Export CSV", msg)

    def open_selection_window(self, title, action_name):
        if not self.checked_items:
            messagebox.showerror(
                "Selection Error",
                f"Please select at least one hardware item from the catalog to {action_name}."
            )
            return

        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("560x380")
        win.config(bg=PURPLE["primary"])

        x = (
            self.root.winfo_x()
            + (self.root.winfo_width() // 2)
            - 280
        )
        y = (
            self.root.winfo_y()
            + (self.root.winfo_height() // 2)
            - 190
        )

        win.geometry(f"560x380+{x}+{y}")

        tk.Label(
            win,
            text=title,
            font=("Arial", 11, "bold"),
            bg=PURPLE["primary"],
            fg="white"
        ).pack(pady=10)

        frame = tk.Frame(
            win,
            bg=PURPLE["panel"]
        )
        frame.pack(
            fill=tk.BOTH,
            expand=True,
            padx=15,
            pady=5
        )

        columns = (
            "Select",
            "Item",
            "Category",
            "Available Qty",
            "Requested Qty"
        )

        tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings",
            style="Purple.Treeview",
            height=8
        )

        col_widths = [60, 170, 140, 90, 90]

        for col, w in zip(columns, col_widths):
            tree.heading(col, text=col)
            tree.column(
                col,
                width=w,
                anchor="center" if col != "Item" and col != "Category" else "w"
            )

        scrollbar = ttk.Scrollbar(
            frame,
            orient=tk.VERTICAL,
            command=tree.yview
        )
        tree.configure(yscrollcommand=scrollbar.set)

        tree.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        popup_checked = set()

        for row_iid in self.checked_items:
            row_data = self.catalog_row_data.get(row_iid)

            if not row_data:
                continue

            request_id = row_data["request_id"]

            try:
                requested_qty = int(row_data["requested_qty"])
            except (ValueError, TypeError):
                requested_qty = 0

            if request_id == "0":
                continue

            available_qty = InventoryController.get_available_qty(
                row_data["item_name"],
                row_data["category"]
            )

            popup_checked.add(row_iid)

            tree.insert(
                "",
                tk.END,
                iid=row_iid,
                values=(
                    "☑",
                    row_data["item_name"],
                    row_data["category"],
                    available_qty,
                    requested_qty
                )
            )

        def on_popup_click(event):
            region = tree.identify("region", event.x, event.y)

            if region == "cell":
                column = tree.identify_column(event.x)

                if column == "#1":
                    item_iid = tree.identify_row(event.y)

                    if item_iid:
                        if item_iid in popup_checked:
                            popup_checked.remove(item_iid)
                        else:
                            popup_checked.add(item_iid)

                        for child in tree.get_children():
                            vals = list(
                                tree.item(child, "values")
                            )
                            vals[0] = (
                                "☑"
                                if child in popup_checked
                                else "☐"
                            )
                            tree.item(
                                child,
                                values=vals
                            )

        tree.bind(
            "<Button-1>",
            on_popup_click
        )

        def confirm_action():
            if not popup_checked:
                messagebox.showerror(
                    "Error",
                    f"Please check at least one item to {action_name}."
                )
                return

            processed = []

            for row_iid in popup_checked:
                row_data = self.catalog_row_data.get(row_iid)

                if not row_data:
                    continue

                request_id = row_data["request_id"]

                if request_id == "0":
                    messagebox.showerror(
                        "Error",
                        "Select a hardware record that has a submitted request."
                    )
                    return

                success, msg = InventoryController.process_borrow_return(
                    row_data["item_name"],
                    row_data["category"],
                    request_id,
                    action_name,
                    self.username
                )

                if not success:
                    messagebox.showerror(
                        "Transaction Error",
                        msg
                    )
                    return

                processed.append(row_data["item_name"])

            win.destroy()
            self.load_inventory()

            if hasattr(self, "user_status_tab"):
                self.load_user_history()

            messagebox.showinfo(
                "Success",
                f"Successfully processed {action_name} for: {', '.join(processed)}"
            )

        tk.Button(
            win,
            text=f"Confirm {action_name.capitalize()}",
            command=confirm_action,
            bg="#27ae60",
            fg="white",
            font=("Arial", 9, "bold"),
            padx=10, pady=5
        ).pack(pady=10)

    def open_history_window(self):
        win = tk.Toplevel(self.root)
        win.title("Activity & Item History")
        win.geometry("750x450")
        win.config(bg=PURPLE["primary"])

        x = (
            self.root.winfo_x()
            + (self.root.winfo_width() // 2)
            - 375
        )
        y = (
            self.root.winfo_y()
            + (self.root.winfo_height() // 2)
            - 225
        )

        win.geometry(f"750x450+{x}+{y}")

        tk.Label(
            win,
            text=f"Transaction & Request History for [{self.username}]",
            font=("Arial", 11, "bold"),
            bg=PURPLE["primary"],
            fg="white"
        ).pack(pady=10)

        frame = tk.Frame(
            win,
            bg=PURPLE["panel"]
        )
        frame.pack(
            fill=tk.BOTH,
            expand=True,
            padx=15,
            pady=10
        )

        columns = (
            "Select",
            "Date",
            "Subject",
            "Item",
            "Category",
            "Max Qty Available",
            "Available Qty Item",
            "Requested Qty",
            "Request Status",
            "Borrowed or Returned Status"
        )

        tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings",
            style="Purple.Treeview",
            height=14
        )

        col_widths = [
            55, 125, 105, 120, 135,
            125, 120, 100, 115, 155
        ]

        for col, w in zip(columns, col_widths):
            tree.heading(col, text=col)
            tree.column(
                col,
                width=w,
                anchor="center" if col in [
                    "Select",
                    "Date",
                    "Max Qty Available",
                    "Available Qty Item",
                    "Requested Qty",
                    "Request Status",
                    "Borrowed or Returned Status"
                ] else "w"
            )

        scrollbar = ttk.Scrollbar(
            frame,
            orient=tk.VERTICAL,
            command=tree.yview
        )
        h_scrollbar = ttk.Scrollbar(
            frame,
            orient=tk.HORIZONTAL,
            command=tree.xview
        )
        tree.configure(
            yscrollcommand=scrollbar.set,
            xscrollcommand=h_scrollbar.set
        )

        tree.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )
        scrollbar.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )
        h_scrollbar.pack(
            side=tk.BOTTOM,
            fill=tk.X
        )

        all_requests = load_persistent_requests()

        for req in reversed(all_requests):
            if self.role != "admin" and req.get("username") != self.username:
                continue

            category = req.get("category", "Others")
            max_qty = InventoryController.get_max_qty(category)
            available_qty = InventoryController.get_available_qty(
                req.get("item", ""),
                category
            )

            tree.insert(
                "",
                tk.END,
                values=(
                    "☐",
                    req.get("date", ""),
                    req.get("subject", ""),
                    req.get("item", ""),
                    category,
                    max_qty,
                    available_qty,
                    req.get("qty", ""),
                    req.get("status", "Pending"),
                    req.get("borrow_status", "Not Borrowed")
                )
            )

    def time_checkin(self):
        self.open_selection_window(
            "Borrow Item Window Pane",
            "borrow item"
        )

    def time_checkout(self):
        self.open_selection_window(
            "Return Item Window Pane",
            "return item"
        )

    def auto_refresh_inventory(self):
        try:
            if hasattr(self, "tree"):
                self.load_inventory()

            if hasattr(self, "user_status_tab"):
                self.load_user_history()

        except tk.TclError:
            return

        self.root.after(
            3000,
            self.auto_refresh_inventory
        )


# ============================================================
# MERGED FROM: LAB ACT 6=midterms/views/request_view.py
# ============================================================
# views/request_view.py

import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3

class UserRequestWindow(tk.Toplevel):
    def __init__(self, parent, student_id=""):
        super().__init__(parent)
        self.title("Campus Hardware Inventory System (USER PANEL)")
        self.geometry("720x550")
        self.configure(bg="#e8e1f0")
        self.student_id_val = student_id
        
        self.current_queue_num = 101
        self.create_widgets()

    def create_widgets(self):
        # Top banner user info
        top_bar = tk.Frame(self, bg="#221100", height=35)
        top_bar.pack(fill="x")
        tk.Label(top_bar, text=f"Logged in as: {self.student_id_val or 'Student'} [USER]", fg="white", bg="#221100", font=("Arial", 10, "bold")).pack(side="left", padx=10, pady=6)

        # Notebook tabs (gaya ng style sa screenshot mo)
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        tab_request = ttk.Frame(notebook)
        notebook.add(tab_request, text="Request Form & Queue")

        # Tabular Request Form inside tab
        form_frame = ttk.LabelFrame(tab_request, text=" Hardware Item Request Form (Tabular) ")
        form_frame.pack(fill="x", padx=10, pady=10)

        fields = [
            ("Name:", "name_entry"),
            ("Student ID:", "id_entry"),
            ("Professor:", "prof_entry"),
            ("Subject:", "subj_entry"),
            ("Schedule:", "sched_entry"),
            ("Hardware Item:", "item_entry"),
            ("Quantity:", "qty_entry")
        ]

        self.entries = {}
        for i, (label_text, key) in enumerate(fields):
            tk.Label(form_frame, text=label_text, font=("Arial", 9)).grid(row=i, column=0, sticky="w", padx=8, pady=4)
            ent = ttk.Entry(form_frame, width=35)
            ent.grid(row=i, column=1, padx=8, pady=4)
            self.entries[key] = ent

        if self.student_id_val:
            self.entries["id_entry"].insert(0, self.student_id_val)

        submit_btn = tk.Button(form_frame, text="Submit Request", bg="#7b4b94", fg="white", font=("Arial", 9, "bold"), command=self.submit_request)
        submit_btn.grid(row=len(fields), column=0, columnspan=2, pady=8)

        # Queue Status Screen & View Form button
        queue_frame = ttk.LabelFrame(tab_request, text=" Live Queue Status ")
        queue_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.queue_label = tk.Label(queue_frame, text="Queuing Number: --", font=("Arial", 13, "bold"), fg="#7b4b94")
        self.queue_label.pack(pady=8)

        self.status_label = tk.Label(queue_frame, text="Status: Waiting for form submission", font=("Arial", 10))
        self.status_label.pack(pady=2)

        btn_row = tk.Frame(queue_frame)
        btn_row.pack(pady=8)

        tk.Button(btn_row, text="View Request Form Details", bg="#d0c0e0", font=("Arial", 9), command=self.view_request_form).pack(side="left", padx=5)
        tk.Button(btn_row, text="Open Hardware Catalog (Inventory)", bg="#7b4b94", fg="white", font=("Arial", 9, "bold"), command=self.open_catalog).pack(side="left", padx=5)

    def submit_request(self):
        name = self.entries["name_entry"].get()
        student_id = self.entries["id_entry"].get()
        professor = self.entries["prof_entry"].get()
        subject = self.entries["subj_entry"].get()
        schedule = self.entries["sched_entry"].get()
        hardware_item = self.entries["item_entry"].get()
        qty = self.entries["qty_entry"].get()

        if not all([name, student_id, professor, subject, schedule, hardware_item, qty]):
            messagebox.showerror("Error", "Please fill out all tabular request fields.")
            return

        conn = sqlite3.connect("inventory.db")
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO requests (name, student_id, professor, subject, schedule, hardware_item, quantity, status, queue_number)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'Queuing', ?)
        ''', (name, student_id, professor, subject, schedule, hardware_item, int(qty), self.current_queue_num))
        conn.commit()
        conn.close()

        messagebox.showinfo("Success", f"Request submitted successfully! Initial Queuing Number: Q-{self.current_queue_num}")
        self.queue_label.config(text=f"Queuing Number: Q-{self.current_queue_num}")
        self.status_label.config(text="Status: In Queue (Auto-advancing every 1 min)")
        
        self.start_queue_automation()
        self.check_approval_status()

    def start_queue_automation(self):
        """Automated queue progression every 1 minute (60,000 ms)"""
        def increment_queue():
            conn = sqlite3.connect("inventory.db")
            cursor = conn.cursor()
            cursor.execute("SELECT status FROM requests WHERE student_id = ? ORDER BY id DESC LIMIT 1", (self.entries["id_entry"].get(),))
            res = cursor.fetchone()
            conn.close()

            if res and res[0].startswith('APP-'):
                return  # Stop if approved na

            self.current_queue_num += 1
            self.queue_label.config(text=f"Queuing Number: Q-{self.current_queue_num} (Auto-progressing)")
            self.after(60000, increment_queue)

        self.after(60000, increment_queue)

    def check_approval_status(self):
        try:
            conn = sqlite3.connect("inventory.db")
            cursor = conn.cursor()
            cursor.execute("SELECT status FROM requests WHERE student_id = ? ORDER BY id DESC LIMIT 1", (self.entries["id_entry"].get(),))
            row = cursor.fetchone()
            conn.close()
            if row:
                status = row[0]
                if status.startswith('APP-'):
                    self.status_label.config(text=f"Status: Approved! Reference Code: {status}")
                    return
                elif status == 'Rejected':
                    self.status_label.config(text="Status: Request Rejected by Admin.")
                    return
        except Exception:
            pass
        self.after(5000, self.check_approval_status)

    def view_request_form(self):
        sid = self.entries["id_entry"].get()
        if not sid:
            messagebox.showwarning("Warning", "Please input Student ID first.")
            return

        conn = sqlite3.connect("inventory.db")
        cursor = conn.cursor()
        cursor.execute("SELECT name, student_id, professor, subject, schedule, hardware_item, quantity, status FROM requests WHERE student_id = ? ORDER BY id DESC LIMIT 1", (sid,))
        row = cursor.fetchone()
        conn.close()

        if row:
            details = (f"--- REQUEST FORM DETAILS ---\n\n"
                       f"Name: {row[0]}\n"
                       f"Student ID: {row[1]}\n"
                       f"Professor: {row[2]}\n"
                       f"Subject: {row[3]}\n"
                       f"Schedule: {row[4]}\n"
                       f"Hardware Item: {row[5]}\n"
                       f"Quantity: {row[6]}\n"
                       f"Status / Approval Code: {row[7]}")
            messagebox.showinfo("Request Form Data", details)
        else:
            messagebox.showwarning("No Data", "No submitted request form found.")

    def open_catalog(self):
        sid = self.entries["id_entry"].get()
        if not sid:
            messagebox.showwarning("Warning", "Please input Student ID first.")
            return
        UserInventoryView(self, sid)


# ============================================================
# MERGED FROM: LAB ACT 6=midterms/views/admin_view.py
# ============================================================
# views/admin_view.py

import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import random

class AdminApprovalWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Campus Hardware Inventory System (ADMIN PANEL)")
        self.geometry("750x420")
        self.configure(bg="#e8e1f0")
        
        self.create_widgets()
        self.load_requests()

    def create_widgets(self):
        top_bar = tk.Frame(self, bg="#221100", height=35)
        top_bar.pack(fill="x")
        tk.Label(top_bar, text="Logged in as: admin [ADMIN APPROVAL PANEL]", fg="white", bg="#221100", font=("Arial", 10, "bold")).pack(side="left", padx=10, pady=6)

        lbl = tk.Label(self, text="Pending & Active Student Hardware Requests", font=("Arial", 11, "bold"), bg="#e8e1f0", fg="#1b365d")
        lbl.pack(pady=8)

        self.tree = ttk.Treeview(self, columns=("ID", "Name", "Student ID", "Item", "Qty", "Status"), show="headings")
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
        self.tree.pack(fill="both", expand=True, padx=10, pady=5)

        btn_frame = tk.Frame(self, bg="#e8e1f0")
        btn_frame.pack(fill="x", padx=10, pady=10)

        tk.Button(btn_frame, text="Approve (Generate Number)", bg="#7b4b94", fg="white", font=("Arial", 9, "bold"), command=lambda: self.update_status('Approved')).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Reject Request", bg="#d9534f", fg="white", font=("Arial", 9, "bold"), command=lambda: self.update_status('Rejected')).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Refresh List", bg="#d0c0e0", font=("Arial", 9), command=self.load_requests).pack(side="right", padx=5)

    def load_requests(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
            
        conn = sqlite3.connect("inventory.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, student_id, hardware_item, quantity, status FROM requests")
        for row in cursor.fetchall():
            self.tree.insert("", "end", values=row)
        conn.close()

    def update_status(self, action):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a request row.")
            return

        item = self.tree.item(selected)
        req_id = item['values'][0]

        conn = sqlite3.connect("inventory.db")
        cursor = conn.cursor()
        
        if action == 'Approved':
            # Mag-generate ng approval code/number pagkatapos i-approve
            approval_code = f"APP-{random.randint(10000, 99999)}"
            cursor.execute("UPDATE requests SET status = ? WHERE id = ?", (approval_code, req_id))
            messagebox.showinfo("Approved", f"Request approved successfully!\nGenerated Approval Number: {approval_code}")
        else:
            cursor.execute("UPDATE requests SET status = 'Rejected' WHERE id = ?", (req_id,))
            messagebox.showinfo("Rejected", "Request has been rejected.")
            
        conn.commit()
        conn.close()
        self.load_requests()


# ============================================================
# MERGED FROM: LAB ACT 6=midterms/views/login_view.py
# ============================================================
# views/login_view.py

import tkinter as tk
from tkinter import messagebox, ttk


class AuthWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("System Auth - Login / Register / Reset")
        self.root.geometry("420x460")
        self.center_window(420, 460)
        self.root.config(bg="#e8dff5")

        self.mode = tk.StringVar(value="login")

        title_lbl = tk.Label(
            root, text="Campus Hardware Inventory", font=("Arial", 14, "bold"), bg="#e8dff5", fg="#2c3e50"
        )
        title_lbl.pack(pady=12)

        mode_frame = tk.Frame(root, bg="#e8dff5")
        mode_frame.pack(pady=5)

        tk.Radiobutton(mode_frame, text="Login", variable=self.mode, value="login", command=self.toggle_mode, font=("Arial", 9, "bold"), bg="#e8dff5", selectcolor="#fff").pack(side=tk.LEFT, padx=8)
        tk.Radiobutton(mode_frame, text="Register", variable=self.mode, value="register", command=self.toggle_mode, font=("Arial", 9, "bold"), bg="#e8dff5", selectcolor="#fff").pack(side=tk.LEFT, padx=8)
        tk.Radiobutton(mode_frame, text="Reset / Unlock", variable=self.mode, value="reset", command=self.toggle_mode, font=("Arial", 9, "bold"), bg="#e8dff5", selectcolor="#fff").pack(side=tk.LEFT, padx=8)

        self.form_frame = tk.Frame(root, bg="#e8dff5")
        self.form_frame.pack(pady=5)

        self.lbl1 = tk.Label(self.form_frame, font=("Arial", 9), bg="#e8dff5", anchor="w")
        self.entry1 = tk.Entry(self.form_frame, font=("Arial", 9), width=24)

        self.lbl_email = tk.Label(self.form_frame, text="Email:", font=("Arial", 9), bg="#e8dff5", anchor="w")
        self.entry_email = tk.Entry(self.form_frame, font=("Arial", 9), width=24)

        self.lbl_pass = tk.Label(self.form_frame, text="Password:", font=("Arial", 9), bg="#e8dff5", anchor="w")
        self.entry_pass = tk.Entry(self.form_frame, font=("Arial", 9), width=24, show="*")

        self.lbl_confirm = tk.Label(self.form_frame, text="Confirm Pass:", font=("Arial", 9), bg="#e8dff5", anchor="w")
        self.entry_confirm = tk.Entry(self.form_frame, font=("Arial", 9), width=24, show="*")

        self.show_pass_var = tk.IntVar(value=0)
        self.show_pass_chk = tk.Checkbutton(
            self.form_frame, text="Show Passwords", variable=self.show_pass_var, command=self.toggle_pass_visibility, font=("Arial", 8), bg="#e8dff5", selectcolor="#fff"
        )

        self.submit_btn = tk.Button(root, command=self.handle_submit, bg="#8b5cf6", fg="white", font=("Arial", 10, "bold"), width=24)
        self.submit_btn.pack(pady=12)

        self.toggle_mode()

    def center_window(self, width, height):
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = int((sw / 2) - (width / 2))
        y = int((sh / 2) - (height / 2))
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def toggle_pass_visibility(self):
        show_char = "" if self.show_pass_var.get() == 1 else "*"
        self.entry_pass.config(show=show_char)
        self.entry_confirm.config(show=show_char)

    def toggle_mode(self):
        for e in [self.entry1, self.entry_email, self.entry_pass, self.entry_confirm]:
            e.delete(0, tk.END)
        self.show_pass_var.set(0)
        self.toggle_pass_visibility()

        for w in [self.lbl1, self.entry1, self.lbl_email, self.entry_email, self.lbl_pass, self.entry_pass, self.lbl_confirm, self.entry_confirm, self.show_pass_chk]:
            w.grid_forget()

        mode = self.mode.get()
        if mode == "login":
            self.submit_btn.config(text="Login", bg="#8e44ad")
            self.lbl1.config(text="Username / Email:")
            self.lbl1.grid(row=0, column=0, sticky="w", pady=5)
            self.entry1.grid(row=0, column=1, pady=5, padx=5)

            self.lbl_pass.config(text="Password:")
            self.lbl_pass.grid(row=1, column=0, sticky="w", pady=5)
            self.entry_pass.grid(row=1, column=1, pady=5, padx=5)
            self.show_pass_chk.grid(row=2, column=1, sticky="w", pady=2)

        elif mode == "register":
            self.submit_btn.config(text="Register", bg="#8e44ad")
            self.lbl1.config(text="Username:")
            self.lbl1.grid(row=0, column=0, sticky="w", pady=4)
            self.entry1.grid(row=0, column=1, pady=4, padx=5)

            self.lbl_email.config(text="Email:")
            self.lbl_email.grid(row=1, column=0, sticky="w", pady=4)
            self.entry_email.grid(row=1, column=1, pady=4, padx=5)

            self.lbl_pass.config(text="Password:")
            self.lbl_pass.grid(row=2, column=0, sticky="w", pady=4)
            self.entry_pass.grid(row=2, column=1, pady=4, padx=5)
            self.show_pass_chk.grid(row=3, column=1, sticky="w", pady=2)

        elif mode == "reset":
            self.submit_btn.config(text="Submit Reset / Unlock Request", bg="#8e44ad")
            
            self.lbl1.config(text="Account Username:")
            self.lbl1.grid(row=0, column=0, sticky="w", pady=4)
            self.entry1.grid(row=1, column=0, pady=4, padx=5)

            self.lbl_email.config(text="Registered Email:")
            self.lbl_email.grid(row=2, column=0, sticky="w", pady=4)
            self.entry_email.grid(row=3, column=0, pady=4, padx=5)

            self.lbl_pass.config(text="Desired New Password:")
            self.lbl_pass.grid(row=4, column=0, sticky="w", pady=4)
            self.entry_pass.grid(row=5, column=0, pady=4, padx=5)

            self.lbl_confirm.config(text="Confirm New Password:")
            self.lbl_confirm.grid(row=6, column=0, sticky="w", pady=4)
            self.entry_confirm.grid(row=7, column=0, pady=4, padx=5)
            
            self.show_pass_chk.grid(row=10, column=0, sticky="w", pady=2)

    def handle_submit(self):
        mode = self.mode.get()
        if mode == "login":
            username_or_email = self.entry1.get().strip()
            password = self.entry_pass.get().strip()

            if not username_or_email or not password:
                messagebox.showerror("Login Error", "Please fill in both fields.")
                return

            success, msg, role = AuthController.authenticate(username_or_email, password)
            if success:
                self.root.destroy()
                main_root = tk.Tk()
                
                conn = get_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT username FROM users WHERE username = ? OR email = ?", (username_or_email, username_or_email))
                row = cursor.fetchone()
                db_uname = row[0] if row else username_or_email
                conn.close()

                InventoryApp(main_root, role=role, username=db_uname)
                main_root.mainloop()
            else:
                messagebox.showerror("Login Error", msg)

        elif mode == "register":
            success, msg = AuthController.register(
                self.entry1.get().strip(), self.entry_email.get().strip(), self.entry_pass.get().strip()
            )
            if success:
                messagebox.showinfo("Success", msg)
                self.mode.set("login")
                self.toggle_mode()
            else:
                messagebox.showerror("Registration Error", msg)

        elif mode == "reset":
            success, msg = AuthController.submit_password_reset(
                self.entry1.get().strip(), self.entry_email.get().strip(),
                self.entry_pass.get().strip(), self.entry_confirm.get().strip()
            )
            if success:
                messagebox.showinfo("Submitted", msg)
                self.mode.set("login")
                self.toggle_mode()
            else:
                messagebox.showerror("Reset Request Error", msg)


# ============================================================
# APPLICATION ENTRY POINT
# ============================================================
if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    AuthWindow(root)
    root.mainloop()
