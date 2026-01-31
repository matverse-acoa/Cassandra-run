import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from cassandra_run.db import Base


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    prev_hash = Column(Text, nullable=False)
    data_hash = Column(Text, nullable=False)
    merkle_root = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String(32), default="PENDING")
    payload = Column(JSON, nullable=False)
    pbse_decision = Column(String(32), default="BLOCK")

    proofs = relationship("Proof", back_populates="event")


class Proof(Base):
    __tablename__ = "proofs"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=False)
    signer = Column(String(128), nullable=False)
    signature = Column(Text, nullable=False)
    signed_at = Column(DateTime, default=datetime.datetime.utcnow)

    event = relationship("Event", back_populates="proofs")
