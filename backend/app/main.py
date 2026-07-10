
from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session

from .database import get_db
from .schemas import EmailCreate
from .services.email_service import process_email


app = FastAPI(
    title="Phishy API",
    version="1.0"
)


@app.get("/")
def root():
    return {
        "message": "Phishy API is running"
    }


@app.post("/emails")
def create_email(
    email: EmailCreate,
    db: Session = Depends(get_db)
):
    return process_email(email, db)
