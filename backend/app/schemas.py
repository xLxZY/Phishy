from pydantic import BaseModel


class EmailCreate(BaseModel):

    sender_email: str

    receiver_email: str

    subject: str

    body: str

    message_id: str | None = None
