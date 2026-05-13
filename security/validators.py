"""
security/validators.py
 
Input validation module.
Every value that arrives from the outside world passes through here.
Untrusted input is the root cause of injection attacks, crashes, and
data corruption — validate before use, always.
"""
import re
from dataclasses import dataclass

@dataclass
class ValidationResult:
    """Outcome of a single validation check.
 
    Attributes:
        valid:   True if the value passed all rules.
        message: Human-readable error description when valid is False.
    """
    valid  : bool
    message: str = ""

def validate_email(email):
    """Check that the value looks like a well-formed email address.
 
    Args:
        email: Raw string supplied by the caller.
 
    Returns:
        ValidationResult with valid=True on success.
    """
    if not email or not isinstance(email):
        return ValidationResult(False, "Email cannot be empty.")
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, email.strip()):
        return ValidationResult(False, f"Invalid email format: {email!r}")
    return ValidationResult(True)

def validate_patient_id(patient_id):
    """Enforce the P### patient ID format (P001 – P999).
 
    Args:
        patient_id: Raw ID string from the request.
 
    Returns:
        ValidationResult with valid=True on success.
    """
    if not patient_id:
        return ValidationResult(False, "Patient ID cannot be empty.")
    if not re.match(r"^P\d{3}$", patient_id):
        return ValidationResult(False, f"Invalid patient ID format: {patient_id!r}")
    return ValidationResult(True)

def validate_age(age):
    """Confirm that age falls within a clinically plausible range.
 
    Args:
        age: Integer age value from the request payload.
 
    Returns:
        ValidationResult with valid=True for ages 1 – 149.
    """
    if not isinstance(age, int):
        return ValidationResult(False, "Age must be an integer.")
    if not (0 < age < 150):
        return ValidationResult(False, f"Age out of valid range: {age}")
    return ValidationResult(True)

def validate_password(password):
    """Enforce minimum password security requirements.
 
    Rules: at least 8 characters, one uppercase letter, one digit.
 
    Args:
        password: Plain-text password chosen by the user.
 
    Returns:
        ValidationResult with valid=True when all rules pass.
    """
    if len(password) < 8:
        return ValidationResult(False, "Password must be at least 8 characters.")
    if not re.search(r"[A-Z]", password):
        return ValidationResult(False, "Password must contain at least one uppercase letter.")
    if not re.search(r"\d", password):
        return ValidationResult(False, "Password must contain at least one digit.")
    return ValidationResult(True)

def sanitize_string(value):
    """Strip characters that could be used in XSS or injection attacks.
 
    Keeps letters, digits, whitespace, hyphens, and full stops.
    Everything else is removed.
 
    Args:
        value: Raw string from user input.
 
    Returns:
        Cleaned string safe to store and display.
    """
    return re.sub(r"[^a-zA-Z0-9\s\-\.]", "", value).strip()