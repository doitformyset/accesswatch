# api/db.py

"""
SQLite + SQLAlchemy setup for AccessWatch.

- Always writes the DB file to the project root (not wherever you run the app from/uvicorn)
- Provides SessionLocal() for per-request DB sessions.
- Declares the Finding ORM model and creates the table on import (dev-friendly).

"""

from sqlalchemy import create_engine, Column, Integer, String, JSON
from sqlalchemy.orm import declarative_base, sessionmaker
from pathlib import Path

# Pin the database URL to the project root (the folder that contains /api)
BASE_DIR = Path(__file__).resolve().parents[1]   # Project root
DATABASE_URL = f"sqlite:///{BASE_DIR / 'accesswatch.db'}"   # SQLite URL format

# Create the SQLAlchemy engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}  # SQLite-specific argument to allow multi-threaded access
)

# Every request will be handled in its own session
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declarative base is used to define tables as Python classes
Base = declarative_base()

# ORM Model: Describes the "Findings" table schema
class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)  # Auto-increment ID
    rule_id = Column(String, index=True)                # Rule identifier (e.g., "AW-AD-001")
    severity = Column(String)                           # Severity level (e.g., "CRITICAL")
    entity_type = Column(String)                        # Type of entity (e.g., "user", "group")
    entity_name = Column(String)                        # Name of the entity (e.g., "john.smith")
    details = Column(JSON)                              # JSON column to store additional details (e.g., group, evidence, source, etc.)
    

    def __repr__(self) -> str:
        return f"<Finding id={self.id}, rule_id={self.rule_id}, severity={self.severity}>"
    
# Create tables if they don't exist
# This runs at import time (safe for local development) In production, use migrations.
Base.metadata.create_all(bind=engine)    

class Group(Base):
    """Simple group catalog. Useful for metadata and UI purposes."""
    __tablename__ = "groups"
    id = Column(Integer, primary_key=True, index=True)
    source = Column(String, default="AD")  # e.g., "AD", "LINUX", "ENTRA"
    name = Column(String, index=True)      # e.g., "Domain Admins"

class Membership(Base):
    # Membership Edges: Who's in what group
    __tablename__ = "memberships"
    id = Column(Integer, primary_key=True, index=True)
    source = Column(String, default="AD")   # e.g., "AD", "LINUX", "ENTRA"
    group_name = Column(String, index=True) # e.g., "Domain Admins"
    member_name = Column(String, index=True) # e.g., "john.smith" or "midcorp\\rita.patel"
    member_type = Column(String, default="user")    # e.g., "user", "group"

# Create tables if they don't exist
Base.metadata.create_all(bind=engine)