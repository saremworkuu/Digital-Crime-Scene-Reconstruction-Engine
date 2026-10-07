from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from pathlib import Path
from app.services.ingestion import analyze_file
import shutil
import uuid

router = APIRouter()

# ensure upload directory exists
UPLOAD_DIR = Path("/app/data/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@router.post("/upload")
async def upload_evidence(file: UploadFile = File(...), case_id: str = Form(...)):
	if not file.filename:
		raise HTTPException(status_code=400, detail="No filename provided")

	# save file
	dest_name = f"{uuid.uuid4().hex}_{file.filename}"
	dest_path = UPLOAD_DIR / dest_name
	with dest_path.open("wb") as out:
		shutil.copyfileobj(file.file, out)

	# run basic analysis
	result = analyze_file(dest_path)

	return {"case_id": case_id, "file": file.filename, "stored_as": dest_name, "analysis": result}
