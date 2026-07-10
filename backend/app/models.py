from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Date
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from .database import Base


class Email(Base):

    __tablename__ = "emails"

    id = Column(Integer, primary_key=True, index=True)

    sender_email = Column(String(255))

    receiver_email = Column(String(255))

    subject = Column(Text)

    body = Column(Text)

    message_id = Column(Text)

    received_at = Column(
        DateTime,
        server_default=func.now()
    )

    status = Column(
        String(50),
        default="NEW"
    )


    urls = relationship(
        "EmailURL",
        back_populates="email",
        cascade="all, delete"
    )

    ips = relationship(
        "EmailIP",
        back_populates="email",
        cascade="all, delete"
    )

    domains = relationship(
        "EmailDomain",
        back_populates="email",
        cascade="all, delete"
    )

    headers = relationship(
        "EmailHeader",
        back_populates="email",
        cascade="all, delete"
    )

    attachments = relationship(
        "Attachment",
        back_populates="email",
        cascade="all, delete"
    )

    threat_analysis = relationship(
        "ThreatAnalysis",
        back_populates="email",
        uselist=False,
        cascade="all, delete"
    )

    jira_ticket = relationship(
        "JiraTicket",
        back_populates="email",
        uselist=False,
        cascade="all, delete"
    )

    incident = relationship(
        "Incident",
        back_populates="email",
        uselist=False,
        cascade="all, delete"
    )
class EmailHeader(Base):

    __tablename__ = "email_headers"

    id = Column(Integer, primary_key=True, index=True)

    email_id = Column(
        Integer,
        ForeignKey("emails.id"),
        nullable=False
    )

    header_name = Column(Text)

    header_value = Column(Text)


    email = relationship(
        "Email",
        back_populates="headers"
    )



class EmailURL(Base):

    __tablename__ = "email_urls"

    id = Column(Integer, primary_key=True, index=True)

    email_id = Column(
        Integer,
        ForeignKey("emails.id"),
        nullable=False
    )

    url = Column(
        Text,
        nullable=False
    )

    domain = Column(String(255))

    reputation_score = Column(Integer)


    email = relationship(
        "Email",
        back_populates="urls"
    )



class EmailDomain(Base):

    __tablename__ = "email_domains"

    id = Column(Integer, primary_key=True, index=True)

    email_id = Column(
        Integer,
        ForeignKey("emails.id"),
        nullable=False
    )

    domain = Column(String(255))

    registrar = Column(Text)

    creation_date = Column(Date)

    reputation_score = Column(Integer)


    email = relationship(
        "Email",
        back_populates="domains"
    )



class EmailIP(Base):

    __tablename__ = "email_ips"

    id = Column(Integer, primary_key=True, index=True)

    email_id = Column(
        Integer,
        ForeignKey("emails.id"),
        nullable=False
    )

    ip_address = Column(String(45))

    country = Column(String(100))

    city = Column(String(100))

    reputation_score = Column(Integer)


    email = relationship(
        "Email",
        back_populates="ips"
    )



class Attachment(Base):

    __tablename__ = "attachments"

    id = Column(Integer, primary_key=True, index=True)

    email_id = Column(
        Integer,
        ForeignKey("emails.id"),
        nullable=False
    )

    filename = Column(Text)

    file_type = Column(Text)

    file_size = Column(Integer)

    sha256_hash = Column(Text)

    reputation_score = Column(Integer)


    email = relationship(
        "Email",
        back_populates="attachments"
    )



class ThreatAnalysis(Base):

    __tablename__ = "threat_analysis"

    id = Column(Integer, primary_key=True, index=True)

    email_id = Column(
        Integer,
        ForeignKey("emails.id"),
        nullable=False
    )

    risk_score = Column(Integer)

    verdict = Column(String(50))

    ai_reason = Column(Text)

    analyzed_at = Column(
        DateTime,
        server_default=func.now()
    )


    email = relationship(
        "Email",
        back_populates="threat_analysis"
    )



class JiraTicket(Base):

    __tablename__ = "jira_tickets"

    id = Column(Integer, primary_key=True, index=True)

    email_id = Column(
        Integer,
        ForeignKey("emails.id"),
        nullable=False
    )

    jira_ticket_id = Column(Text)

    jira_url = Column(Text)

    status = Column(String(50))

    created_at = Column(
        DateTime,
        server_default=func.now()
    )


    email = relationship(
        "Email",
        back_populates="jira_ticket"
    )


class Incident(Base):

    __tablename__ = "incidents"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    email_id = Column(
        Integer,
        ForeignKey("emails.id"),
        nullable=False
    )

    severity = Column(
        String(50)
    )

    verdict = Column(
        String(50)
    )

    risk_score = Column(
        Integer
    )

    created_at = Column(
        DateTime,
        server_default=func.now()
    )
