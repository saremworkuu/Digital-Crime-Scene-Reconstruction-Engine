from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict
from uuid import uuid4

router = APIRouter()

# In-memory store for demo purposes
_CASES: Dict[str, Dict] = {}


class CaseCreate(BaseModel):
	title: str
	description: str | None = None


class CaseOut(BaseModel):
	id: str
	title: str
	description: str | None = None


@router.post("/", response_model=CaseOut)
def create_case(payload: CaseCreate):
	case_id = str(uuid4())
	data = {"id": case_id, "title": payload.title, "description": payload.description}
	_CASES[case_id] = data
	return data


@router.get("/{case_id}", response_model=CaseOut)
def get_case(case_id: str):
	case = _CASES.get(case_id)
	if not case:
		raise HTTPException(status_code=404, detail="Case not found")
	return case
