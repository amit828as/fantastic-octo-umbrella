from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.database.connection import Base


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True, nullable=False)
    admin_email = Column(String(255), unique=True, index=True, nullable=False)
    admin_password_hash = Column(String(255), nullable=False)
    dynamic_db_connection_string = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationship to admins
    admins = relationship("Admin", back_populates="organization")

    def __repr__(self):
        return f"<Organization(id={self.id}, name='{self.name}')>" 