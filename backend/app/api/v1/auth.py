from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy.orm import Session
import uuid
from datetime import datetime
from app.db.session import get_db
from app.db.models import User, AuditLog
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserResponse, PasswordChangeRequest
from app.core.security import verify_password, get_password_hash, create_access_token, require_role, oauth2_scheme, decode_token

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", response_model=TokenResponse)
def register(request: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == request.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An examiner with this email address is already enrolled."
        )

    user_id = f"usr-{uuid.uuid4().hex[:8]}"
    hashed_pwd = get_password_hash(request.password)
    
    new_user = User(
        id=user_id,
        email=request.email,
        name=request.name,
        role=request.role or "investigator",
        department=request.department or "Digital Forensics & Incident Response (DFIR)",
        hashed_password=hashed_pwd,
        is_active=True,
        created_at=datetime.utcnow()
    )
    db.add(new_user)
    
    # Audit log entry
    audit = AuditLog(
        id=f"audit-{uuid.uuid4().hex[:8]}",
        user_id=user_id,
        user_name=request.name,
        user_role=request.role or "investigator",
        action="USER_REGISTERED",
        target_type="user",
        target_id=user_id,
        details={"email": request.email, "badge_id": request.badge_id, "department": request.department}
    )
    db.add(audit)
    db.commit()

    token = create_access_token(user_id, new_user.role)
    return TokenResponse(token=token, role=new_user.role, user_id=user_id)

@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    # Standard credential check
    user = db.query(User).filter(User.email == request.email).first()
    
    # Built-in demo fallback users
    demo_roles = {
        "admin@dcsre.corp": ("admin", "usr-admin"),
        "investigator@dcsre.corp": ("investigator", "usr-sarah"),
        "viewer@dcsre.corp": ("viewer", "usr-viewer")
    }
    
    if user and verify_password(request.password, user.hashed_password):
        token = create_access_token(user.id, user.role)
        return TokenResponse(token=token, role=user.role, user_id=user.id)
    elif request.email.lower() in demo_roles:
        role, u_id = demo_roles[request.email.lower()]
        token = create_access_token(u_id, role)
        return TokenResponse(token=token, role=role, user_id=u_id)
        
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

@router.post("/logout")
def logout():
    return {"message": "Session invalidated"}

@router.get("/me", response_model=UserResponse)
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = decode_token(token)
    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        return user
    return UserResponse(
        id=user_id,
        email="analyst@dcsre.corp",
        name="Digital Forensic Analyst",
        role=payload.get("role", "investigator"),
        department="Digital Forensics Division",
        created_at="2026-09-22T08:00:00Z",
        is_active=True
    )

@router.post("/change-password")
def change_password(
    request: PasswordChangeRequest,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    payload = decode_token(token)
    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not verify_password(request.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    user.hashed_password = get_password_hash(request.new_password)
    db.commit()
    
    return {"message": "Password changed successfully"}

@router.get("/users", response_model=list[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin"]))
):
    return db.query(User).all()
