from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session
from app.auth.jwt_handler import verify_token
from app.database import get_db
from app.models import User

bearer_scheme = HTTPBearer(auto_error=False)

def unauthorized(detail: str):
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, headers={"WWW-Authenticate": "Bearer"})

def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme), db: Session = Depends(get_db)) -> User:
    if not credentials: raise unauthorized("Потрібна автентифікація")
    try:
        payload = verify_token(credentials.credentials)
    except JWTError:
        raise unauthorized("Невалідний або протермінований токен")
    if payload.get("type") != "access": raise unauthorized("Потрібен access token")
    
    user = db.get(User, int(payload.get("sub")))
    if not user or not user.is_active: raise unauthorized("Користувача не знайдено")
    return user

def require_role(*allowed_roles: str):
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if not {r.name for r in current_user.roles}.intersection(allowed_roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Доступ заборонено")
        return current_user
    return role_checker
