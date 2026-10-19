
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.models.case import Case
from app.db.models.evidence import Evidence
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.evidence import EvidenceCreate, EvidenceResponse

router = APIRouter()


@router.post(
    "/",
    response_model=EvidenceResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_evidence(
    data: EvidenceCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    case = db.execute(
        select(Case).where(Case.id == data.case_id)
    ).scalar_one_or_none()

    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found.",
        )

    if case.created_by != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to manage evidence for this case.",
        )

    evidence = Evidence(
        case_id=data.case_id,
        filename=data.filename,
        file_type=data.file_type,
        file_size=data.file_size,
    )

    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    return evidence


@router.get("/", response_model=list[EvidenceResponse])
def list_evidence(
    case_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    import uuid

    try:
        case_uuid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid case ID.",
        )

    case = db.execute(
        select(Case).where(Case.id == case_uuid)
    ).scalar_one_or_none()

    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found.",
        )

    if case.created_by != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to view evidence for this case.",
        )

    result = db.execute(
        select(Evidence).where(Evidence.case_id == case_uuid)
    )

    return result.scalars().all()
