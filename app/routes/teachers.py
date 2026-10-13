from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.auth.dependencies import require_role
from app.database import get_db
from app.models import Grade, Subject, User
from app.schemas import GradeCreate

router = APIRouter(prefix="/teachers", tags=["Teachers"])

@router.post("/grades", status_code=status.HTTP_201_CREATED)
def add_grade(data: GradeCreate, current_user: User = Depends(require_role("teacher", "admin")), db: Session = Depends(get_db)):
    grade = Grade(student_id=data.student_id, subject_id=data.subject_id, grade=data.grade, comment=data.comment, assigned_by=current_user.id)
    db.add(grade)
    db.commit()
    return {"status": "success"}
