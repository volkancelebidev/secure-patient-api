# Secure Patient API

A production-style healthcare API security layer built in pure Python.
Demonstrates the eight security controls that every real-world patient
data system must implement before going live.

No HTTP framework required — each security layer is isolated in its own
module and fully testable without a running server. The same functions
plug directly into FastAPI route handlers and dependency injectors.

---

## Security Architecture
```
Incoming Request
│
▼
┌─────────────────┐
│  Rate Limiting  │  Blocks brute-force and DoS attempts per IP
└────────┬────────┘
│
▼
┌─────────────────┐
│Input Validation │  Rejects malformed IDs, emails, ages, passwords
└────────┬────────┘
│
▼
┌─────────────────┐
│ JWT Verification│  Confirms identity and role from signed token
└────────┬────────┘
│
▼
┌─────────────────┐
│  Business Logic │  Role-based access control enforced here
└────────┬────────┘
│
▼
┌─────────────────┐
│  PHI Protection │  Masks phone, email; strips password_hash
└────────┬────────┘
│
▼
┌─────────────────┐
│  Audit Logging  │  Immutable record: who, what, when, outcome
└─────────────────┘
```
---

## Security Layers

| Layer | Module | What it does |
|-------|--------|--------------|
| Secrets Management | `.env` + `python-dotenv` | `SECRET_KEY` and `API_KEY` never hardcoded |
| Password Hashing | `security/auth.py` | bcrypt with per-password salt; plain text never stored |
| JWT Authentication | `security/auth.py` | HS256 signed token; 24-hour expiry; role embedded |
| Input Validation | `security/validators.py` | Email regex, P### ID format, age range, password strength |
| SQL Injection Prevention | `secure_patient_api.py` | Parameterised `?` placeholders throughout |
| Rate Limiting | `security/rate_limiter.py` | Sliding-window; 3 login attempts / 10 general requests per minute |
| Audit Logging | `security/audit.py` | Structured log: `user=`, `action=`, `resource=`, `status=` |
| PHI Protection | `security/phi.py` | Phone/email masking; SHA-256 anonymisation; password_hash stripped from responses |

---

## Project Structure
```
secure-patient-api/
├── secure_patient_api.py   # API layer — five endpoints, seven demo scenarios
├── security/
│   ├── init.py
│   ├── auth.py             # bcrypt hashing + JWT create/verify
│   ├── validators.py       # ValidationResult dataclass + five validators
│   ├── rate_limiter.py     # Sliding-window RateLimiter
│   ├── audit.py            # log_event() + log_phi_access()
│   └── phi.py              # mask_phone(), mask_email(), anonymize_id()
└── .gitignore
```
---

## Demo Scenarios

| # | Scenario | Security layer tested |
|---|----------|-----------------------|
| 1 | Successful login + patient retrieval | JWT, PHI masking |
| 2 | Wrong password | bcrypt verify |
| 3 | Brute-force login (4 attempts) | Rate limiting |
| 4 | Tampered / fake JWT | Token verification |
| 5 | Invalid patient ID format | Input validation |
| 6 | Nurse tries to add a patient | Role-based access control |
| 7 | Doctor adds patient with XSS in name | String sanitisation |

---

## How to Run

```bash
git clone https://github.com/volkancelebidev/secure-patient-api.git
cd secure-patient-api
pip install python-dotenv bcrypt PyJWT
```

Create a `.env` file in the project root:
```
SECRET_KEY=your-secret-key-here
API_KEY=your-api-key-here
```
```bash
python secure_patient_api.py
```

---

## Compliance Notes

| Regulation | Controls applied |
|------------|-----------------|
| GDPR (EU) | PHI masking, audit logging, right to erasure (password_hash stripped) |
| KVKK (Turkey) | Same controls as GDPR — directly applicable |
| HIPAA (US) | PHI access audit trail via `log_phi_access()` |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.12 |
| Password hashing | bcrypt |
| Authentication | PyJWT (HS256) |
| Secrets | python-dotenv |
| Database | SQLite (via built-in sqlite3) |
| Rate limiting | In-process sliding window (Redis in production) |
