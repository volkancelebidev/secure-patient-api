"""
security/audit.py
 
Audit logging module.
Records who did what, when, and whether it succeeded.
 
GDPR and HIPAA require that every access to protected health information
is logged in a tamper-evident, long-term store.  In production, these
records are forwarded to an immutable system such as AWS CloudTrail,
Splunk, or a write-once database table.
"""

import logging

# Dedicated audit logger — kept separate from the application logger
# so audit records can be routed to a different handler in production.
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)

_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter(
    "%(asctime)s [AUDIT] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
))
audit_logger.addHandler(_handler)

def log_event(
        user_id : str,
        action  : str,
        resource: str,
        success : bool,
        detail  : str = "",
):
    """Record a security-relevant event.
 
    Args:
        user_id:  Identifier of the user performing the action.
        action:   Verb describing the operation (LOGIN, READ, UPDATE …).
        resource: Target of the action (e.g. "patient:P001", "auth").
        success:  True if the operation completed successfully.
        detail:   Optional extra context such as an error message.
    """
    status = "SUCCESS" if success else "FAILED"
    message = f"user={user_id} action={action} resource={resource} status={status}"
    if detail:
        message += f" detail={detail!r}"
    audit_logger.info(message)

def log_phi_access(user_id, patient_id, fields):
    """Record access to Protected Health Information fields.
 
    HIPAA and GDPR require PHI access to be logged separately from
    general application events so it can be reported independently.
 
    Args:
        user_id:    Identifier of the user accessing the data.
        patient_id: Identifier of the patient whose data was accessed.
        fields:     List of field names that were read or modified.
    """
    # ",".join(fields) → converts the list to a single comma-separated string
    audit_logger.info(
        "user=%s PHI_ACCESS patient=%s fields=%s",
        user_id, patient_id, ",".join(fields),
    )

