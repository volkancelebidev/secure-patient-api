"""
secure_patient_api.py
 
A production-style secure patient API simulator.
Demonstrates all eight security layers that a real FastAPI healthcare
application requires, implemented in plain Python so each layer is
visible and testable without an HTTP server.
 
Security layers applied per endpoint:
    1. Secrets Management  — SECRET_KEY and API_KEY loaded from .env
    2. Password Hashing    — bcrypt at registration; verify at login
    3. JWT Authentication  — signed token issued at login, verified per request
    4. Input Validation    — email, patient ID, age, password strength
    5. SQL Injection       — parameterised queries throughout
    6. Rate Limiting       — sliding-window limiter per IP
    7. Audit Logging       — every action logged with user and outcome
    8. PHI Protection      — sensitive fields masked before leaving the API
 
In a real FastAPI project the same security functions are called from
route handlers and dependency injectors — the logic is identical.
"""

import logging
import os
import sqlite3
from dotenv import load_dotenv

from security.auth   import hash_password, verify_password, create_access_token, verify_access_token
from security.validators  import validate_email, validate_patient_id, validate_age, validate_password, sanitize_string
from security.rate_limiter  import RateLimiter
from security.audit  import log_event, log_phi_access
from security.phi  import sanitize_for_response, anonymize_id


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

load_dotenv()  # read .env into the process environment

logging.basicConfig(
    level  = logging.WARNING,  # suppress INFO noise; AUDIT records still visible
    format = "%(asctime)s [%(levelname)s] %(message)s",
    datefmt= "%H:%M:%S",
)

SECRET_KEY = os.getenv("SECRET_KEY")
API_KEY    = os.getenv("API_KEY")

if not SECRET_KEY or not API_KEY:
    raise ValueError("Required environment variables are not set. Check your .env file.")


# ---------------------------------------------------------------------------
# Database layer
# ---------------------------------------------------------------------------

class PatientDatabase:
    """SQLite-backed storage for users and patients.
 
    Every query uses parameterised placeholders (?) so user-supplied
    values are never interpolated directly into SQL strings.
 
    Args:
        db_path: Path to the SQLite file.  Uses a file so the same
                 connection is not required across all operations.
    """
    def __init__(self, db_path: str = "clinic_secure.db"):
        self.db_path = db_path
        self._setup()

    def _setup(self):
        """Create the schema if it does not already exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                    PRAGMA foreign_key = ON;
                               
                    CREATE TABLE IF NOT EXISTS users (
                            user_id         TEXT PRIMARY KEY,
                            username        TEXT NOT NULL UNIQUE,
                            password_hash   TEXT NOT NULL,
                            role            TEXT NOT NULL DEFAULT 'nurse');
                               
                    CREATE TABLE IF NOT EXISTS patients (
                            patient_id  TEXT PRIMARY KEY,
                            name        TEXT NOT NULL,
                            age         INTEGER NOT NULL,
                            email       TEXT,
                            phone       TEXT,
                            blood_type  TEXT,
                            diagnosis   TEXT);""")
            
    def add_user(self, user_id, username, password_hash, role):
        """Persist a user record.  INSERT OR IGNORE prevents duplicates."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO users"
                "(user_id, username, password_hash, role) VALUES (?, ?, ?, ?)",
                (user_id, username, password_hash, role),
            )

    def get_user(self, username):
        """Retrieve a user by username.
 
        Returns:
            User dict, or None if not found.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,),  # single-element tuple — trailing comma required
            ).fetchone()
        return dict(row) if row else None
    
    def add_patient(self, patient_id, name, age, email, phone, blood_type, diagnosis):
        """Persist a patient record."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT OR IGNORE INTO patients
                (patient_id, name, age, email, phone, blood_type, diagnosis)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (patient_id, name, age, email, phone, blood_type, diagnosis),
            )

    def get_patient(self, patient_id):
        """Retrieve a patient by primary key.
 
        Returns:
            Patient dict, or None if not found.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM patients WHERE patient_id = ?",
                (patient_id,),
            ).fetchone()
        return dict(row) if row else None
    
    def get_all_patients(self):
        """Return all patients ordered alphabetically."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM patients ORDER BY name"
            ).fetchall()
        return [dict(row) for row in rows]
    


# ---------------------------------------------------------------------------
# API layer
# ---------------------------------------------------------------------------

class SecurePatientAPI:
    """Secure patient API with all eight security layers applied.
 
    Each public method represents one API endpoint.  The security
    pipeline per endpoint is:
        Rate Limit → Validate Input → Verify Token → Business Logic
        → PHI Mask → Audit Log → Return Response
    """

    def __init__(self):
        self.db = PatientDatabase()

        # Separate limiters — login is stricter to slow brute-force attacks
        self.login_limiter   = RateLimiter(max_requests=3, window_seconds=60)
        self.general_limiter = RateLimiter(max_requests=10, window_seconds=60)

        self._seed()

    def _seed(self):
        """Populate the database with demo users and patients."""
        self.db.add_user("U001", "dr.mitchell", hash_password("SecurePass1!"), "doctor")
        self.db.add_user("U002", "nurse.jones",  hash_password("NursePass2@"), "nurse")

        self.db.add_patient("P001", "James Anderson",  52, "james@email.com",  "+1-555-1001", "A+",  "Hypertension")
        self.db.add_patient("P002", "Sophia Martinez", 67, "sophia@email.com", "+1-555-1002", "B-",  "Type 2 Diabetes")
        self.db.add_patient("P003", "Liam Johnson",    34, "liam@email.com",   "+1-555-1003", "O+",  "Migraine")

    
    # ------------------------------------------------------------------
    # Endpoint 1 — Register
    # ------------------------------------------------------------------
    def register(self, ip, user_id, username, email, password, role):
        """Register a new user account.
 
        Security layers: Rate Limit → Email Validation →
                         Password Validation → bcrypt Hash → Audit Log.
 
        Args:
            ip:       Caller IP address used for rate limiting.
            user_id:  Unique identifier for the new account.
            username: Display name / login name.
            email:    Contact email — validated before storage.
            password: Plain-text password — hashed before storage.
            role:     Permission level; defaults to "nurse".
 
        Returns:
            Response dict with success flag and message or error.
        """
        if not self.general_limiter.is_allowed(ip):
            log_event(user_id, "REGISTER", "auth", False, "Rate limit exceeded")
            return {"success": False, "error": "Too many requests. Try again later."}
        
        email_check = validate_email(email)
        if not email_check.valid:
            log_event(user_id, "REGISTER", "auth", False, email_check.message)
            return {"success": False, "error": email_check.message}
        
        pass_check = validate_password(password)
        if not pass_check.valid:
            log_event(user_id, "REGISTER", "auth", False, pass_check.message)
            return {"success": False, "error": pass_check.message}
        
        # Hash before storing — plain-text passwords never touch the database
        self.db.add_user(user_id, username, hash_password(password), role)
        log_event(user_id, "REGISTER", "auth", True)
        return {"success": True, "message": f"User {username!r} registered successfully."}
    

    # ------------------------------------------------------------------
    # Endpoint 2 — Login
    # ------------------------------------------------------------------

    def login(self, ip, username, password):
        """Authenticate a user and issue a JWT access token.
 
        Security layers: Strict Rate Limit → DB Lookup →
                         bcrypt Verify → JWT Issue → Audit Log.
 
        The error message is intentionally generic — "Invalid credentials"
        regardless of whether the username or password was wrong.
        Distinguishing the two would help an attacker enumerate valid usernames.
 
        Args:
            ip:       Caller IP address.
            username: Account login name.
            password: Plain-text password attempt.
 
        Returns:
            Response dict containing access_token on success.
        """
        if not self.login_limiter.is_allowed(ip):
            log_event("unknown", "LOGIN", f"user:{username}", False, "Rate limit exceeded")
            return {"success":False, "error": "Too many login attempts. Try again in 1 minute."}
        
        user = self.db.get_user(username)
        if not user:
            log_event("unknown", "LOGIN", f"user:{username}", False, "User not found")
            return {"success":False, "error": "Invalid credentials."}
        
        if not verify_password(password, user["password_hash"]):
            log_event(user["user_id"], "LOGIN", f"user:{username}", False, "Wrong password")
            return {"success":False, "error": "Invalid credentials."}
        
        token = create_access_token(user["user_id"], user["role"])
        log_event(user["user_id"], "LOGIN", f"user:{username}",True)

        return {
            "success"      : True,
            "access_token" : token,
            "role"         : user["role"],
            "message"      : "Login successful.",
        }
    
    # ------------------------------------------------------------------
    # Endpoint 3 — Get patient
    # ------------------------------------------------------------------

    def get_patient(self, ip, token, patient_id):
        """Retrieve a single patient record with PHI masking.
 
        Security layers: Rate Limit → JWT Verify → ID Validation →
                         DB Lookup → PHI Mask → PHI Audit Log → Audit Log.
 
        Args:
            ip:         Caller IP address.
            token:      JWT access token from the Authorization header.
            patient_id: Patient identifier in P### format.
 
        Returns:
            Response dict containing the masked patient record.
        """
        if not self.general_limiter.is_allowed(ip):
            return {"success":False, "error": "Too many requests."}
        
        payload = verify_access_token(token)
        if not payload:
            log_event("unknown", "READ", f"patient:{patient_id}", False, "Invalid token")
            return {"success":False, "error": "Invalid or expired token."}
        
        user_id = payload["user_id"]

        id_check = validate_patient_id(patient_id)
        if not id_check.valid:
            log_event(user_id, "READ", f"patient:{patient_id}", False, id_check.message)
            return {"success":False, "error": id_check.message}
        
        patient = self.db.get_patient(patient_id)
        if not patient:
            log_event(user_id, "READ", f"patient:{patient_id}", False, "Not found")
            return {"success":False, "error": "Patient not found."}
        
        # Log PHI access before masking — required by HIPAA / GDPR
        log_phi_access(user_id, patient_id, ["name", "age", "email", "phone", "diagnosis"])

        log_event(user_id, "READ", f"patient:{patient_id}", True)
        return {"success":True, "patient": sanitize_for_response(patient)}
    

    # ------------------------------------------------------------------
    # Endpoint 4 — Add patient
    # ------------------------------------------------------------------
    def add_patient(self, ip, token, patient_data):
        """Register a new patient record.
 
        Security layers: Rate Limit → JWT Verify → Role Check →
                         Input Validation → String Sanitisation → Audit Log.
 
        Only users with the "doctor" role may add patients.
 
        Args:
            ip:           Caller IP address.
            token:        JWT access token.
            patient_data: Dict containing the new patient's fields.
 
        Returns:
            Response dict confirming creation or describing the error.
        """
        if not self.general_limiter.is_allowed(ip):
            return {"success":False, "error": "Too many requests."}
        
        payload = verify_access_token(token)
        if not payload:
            return {"success": False, "error": "Invalid or expired token."}
        
        user_id = payload["user_id"]

        # Role-based access control — nurses cannot add patients
        if payload["role"] != "doctor":
            log_event(user_id, "ADD_PATIENT", "patients", False, "Insufficient permissions")
            return {"success": False, "error": "Only doctors can add patients."}
        
        id_check = validate_patient_id(patient_data.get("patient_id", ""))
        age_check = validate_age(patient_data.get("age", 0))

        if not id_check.valid:
            return {"success": False, "error": id_check.message}
        if not age_check.valid:
            return {"success": False, "error": age_check.message}
        
        # sanitize_string() removes characters used in XSS attacks
        name = sanitize_string(patient_data.get("name", ""))

        self.db.add_patient(
            patient_id = patient_data["patient_id"],
            name       = name,
            age        = patient_data["age"],
            email      = patient_data.get("email", ""),
            phone      = patient_data.get("phone", ""),
            blood_type = patient_data.get("blood_type", ""),
            diagnosis  = patient_data.get("diagnosis", ""),
        )

        log_event(user_id, "ADD_PATIENT", f"patient:{patient_data['patient_id']}", True)
        return {"success":True, "message": f"Patient {patient_data['patient_id']} added."}
    

    # ------------------------------------------------------------------
    # Endpoint 5 — List patients
    # ------------------------------------------------------------------

    def list_patients(self, ip, token):
        """Return all patients with PHI fields masked.
 
        Safe for use in reports and analytics — no raw personal data leaves.
 
        Args:
            ip:    Caller IP address.
            token: JWT access token.
 
        Returns:
            Response dict with masked patient list and total count.
        """
        if not self.general_limiter.is_allowed(ip):
            return {"success":False, "error": "Too many requests."}
        
        payload = verify_access_token(token)
        if not payload:
            return {"success":False, "error": "Invalid or expired token."}
        
        patients = self.db.get_all_patients()
        # sanitize_for_response() applied to every record before returning
        safe = [sanitize_for_response(p) for p in patients]

        log_event(payload["user_id"], "LIST_PATIENTS", "patients", True)
        return {"success":True, "patients": safe, "count": len(safe)}
    
# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def _show(title, response):
    """Print a formatted API response."""
    icon = "✅" if response.get("success") else "❌"
    print(f"\n  {icon} {title}")
    for key, val in response.items():
        if key != "success":
            print(f"    {key}: {val}")

def main():
    """Run seven security scenarios against the API."""

    print("[+] Secure Patient API - starting\n")
    api = SecurePatientAPI()
    sep = "=" * 60

    # Scenario 1 — Successful login and patient access
    print(f"\n{sep}\n SCENARIO 1 - Successful login and patient access\n{sep}")
    result = api.login("10.0.0.1", "dr.mitchell", "SecurePass1!")
    _show("Login as dr.mitchell", result)
    if result["success"]:
        token = result["access_token"]
        _show("Get patient P001", api.get_patient("10.0.0.1", token, "P001"))
        _show("List all patients", api.list_patients("10.0.0.1", token))

    # Scenario 2 — Wrong password
    print(f"\n{sep}\n  SCENARIO 2 - Wrong password\n{sep}")
    _show("Login with wrong password", api.login("10.0.0.2", "dr.mitchell", "wrongpass"))

    # Scenario 3 — Rate limiting (brute force)
    print(f"\n{sep}\n  SCENARIO 3 - Rate limiting (brute force)\n{sep}")
    for i in range(4):
        _show(f"Login attemp {i+1}", api.login("10.0.0.3", "dr.mitchell", "wrong"))

    # Scenario 4 — Invalid JWT token
    print(f"\n{sep}\n  SCENARIO 4 - Invalid JWT token\n{sep}")
    _show("Get patient with fake token", api.get_patient("10.0.0.1", "fake.token.here", "P001"))

    # Scenario 5 — Input validation failure
    print(f"\n{sep}\n SCENARIO 5 - Input validation\n{sep}")
    result2 = api.login("10.0.0.4", "dr.mitchell", "SecurePass1!")
    if result2["success"]:
        _show("Get patient with invalid ID",
              api.get_patient("10.0.0.4", result2["access_token"], "INVALID_ID"))
        
    
    # Scenario 6 — Unauthorised action (nurse cannot add patients)
    print(f"\n{sep}\n SCENARIO 6 - Role check (nurse tries to add patient)\n{sep}")
    nurse = api.login("10.0.0.5", "nurse.jones", "NursePass2@")
    if nurse["success"]:
        _show("Nurse tries to add patient",
        api.add_patient("10.0.0.5", nurse["access_token"],
                        {"patient_id": "P099", "name": "Test", "age": 30}))
        
    # Scenario 7 — Doctor adds patient (XSS attempt in name)
    print(f"\n{sep}\n SCENARIO 7 - Doctor adds patient (XSS attempt sanitised)\n{sep}")
    if result["success"]:
        _show("Add patient with XSS in name",
              api.add_patient("10.0.0.1", token, {
                  "patient_id": "P004",
                  "name"      : "Emma<script>Wilson",
                  "age"       : 44,
                  "email"     : "emma@email.com",
                  "phone"     : "+1-555-1004",
                  "blood_type": "0+",
                  "diagnosis" : "Anxiety",
              }))
        _show("Get P004 (name sanitised?)", api.get_patient("10.0.0.1", token, "P004"))

    print(f"\n{sep}\n All scenarios completed.\n{sep}")

if __name__ == "__main__":
    main()
 
 