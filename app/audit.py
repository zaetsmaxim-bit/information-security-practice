from datetime import datetime, timedelta, timezone
from fastapi import Request
from sqlalchemy.orm import Session
from app.models import AuditLog

BRUTE_FORCE_WINDOW_MINUTES = 5
BRUTE_FORCE_MAX_ATTEMPTS = 5


def get_client_ip(request: Request | None) -> str:
    if request is None:
        return "unknown"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def log_event(
    db: Session,
    action: str,
    status: str = "SUCCESS",
    user_id: int | None = None,
    username: str | None = None,
    resource: str | None = None,
    resource_id: int | None = None,
    status_code: int = 200,
    details: str | None = None,
    request: Request | None = None,
) -> AuditLog:
    ip_addr = get_client_ip(request)
    ua = request.headers.get("User-Agent", "")[:255] if request else None
    entry = AuditLog(
        timestamp=datetime.now(timezone.utc),
        user_id=user_id,
        username=username,
        action=action,
        resource=resource,
        resource_id=resource_id,
        ip_address=ip_addr,
        user_agent=ua,
        status=status,
        status_code=status_code,
        details=details,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def is_brute_force(db: Session, username: str, ip_address: str) -> bool:
    since = datetime.now(timezone.utc) - timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
    failed_count = (
        db.query(AuditLog)
        .filter(
            AuditLog.action == "login_failed",
            AuditLog.timestamp >= since,
            (AuditLog.username == username) | (AuditLog.ip_address == ip_address),
        )
        .count()
    )
    return failed_count >= BRUTE_FORCE_MAX_ATTEMPTS
