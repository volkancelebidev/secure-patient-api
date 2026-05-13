"""
security/phi.py
 
Protected Health Information (PHI) protection module.
Masks or anonymises sensitive patient fields before they are logged,
returned in API responses, or used in analytics.
 
Relevant regulations: GDPR (EU), KVKK (Turkey), HIPAA (US).
"""

import hashlib
import re

def mask_phone(phone):
    """Mask all but the last four digits of a phone number.
 
    Args:
        phone: Raw phone number string.
 
    Returns:
        Masked string such as "****-****-1234".
    """
    if len(phone) <= 4:
        return "****"
    return "*" * (len(phone) - 4) + phone[-4:]

def mask_email(email):
    """Mask the username portion of an email address.
 
    The first two characters remain visible; the rest are replaced
    with asterisks so the address is recognisable but not usable.
 
    Args:
        email: Raw email address string.
 
    Returns:
        Masked string such as "al***@hospital.com".
    """
    parts = email.split("@")
    if len(parts) != 2:
        return "***@***.***"
    username = parts[0][:2] + "*" * max(0, len(parts[0]) - 2)
    return f"{username}@{parts[1]}"

def anonymize_id(patient_id):
    """Produce a consistent pseudonym for a patient ID.
 
    SHA-256 is one-way — the original ID cannot be recovered.
    The same patient_id always maps to the same pseudonym so
    longitudinal analysis remains possible without exposing identity.
 
    Args:
        patient_id: Original patient identifier.
 
    Returns:
        16-character hex pseudonym.
    """
    return hashlib.sha256(patient_id.encode()).hexdigest()[:16]

def sanitize_for_response(patient):
    """Remove or mask PHI fields before sending a patient record to a caller.
 
    In production this is handled by a Pydantic response model in FastAPI.
    The manual approach here makes the masking logic explicit.
 
    Args:
        patient: Raw patient dict as returned by the database layer.
 
    Returns:
        A copy of the dict with sensitive fields masked and secret
        fields removed entirely.
    """
    safe = patient.copy()

    if "phone" in safe and safe["phone"]:
        safe["phone"] = mask_phone(safe["phone"])
    if "email" in safe and safe["email"]:
        safe["email"] = mask_email(safe["email"])

    # These fields must never leave the backend
    safe.pop("password_hash", None)
    safe.pop("ssn", None)

    return safe