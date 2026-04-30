from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean,
    ForeignKey, Text, UniqueConstraint
)
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

try:
    from .database import Base
except ImportError:
    from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    phone_number = Column(String, unique=True, index=True, nullable=False)
    display_name = Column(String, nullable=True)
    avatar_url = Column(String, nullable=True)
    public_key = Column(Text, nullable=True)        # JWK string for E2EE ECDH
    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Contact(Base):
    __tablename__ = "contacts"
    __table_args__ = (UniqueConstraint("owner_phone", "contact_phone"),)

    id = Column(Integer, primary_key=True, index=True)
    owner_phone = Column(String, index=True, nullable=False)
    contact_phone = Column(String, index=True, nullable=False)
    nickname = Column(String, nullable=True)
    added_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    avatar_url = Column(String, nullable=True)
    created_by = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    members = relationship("GroupMember", cascade="all, delete-orphan", lazy="select")


class GroupMember(Base):
    __tablename__ = "group_members"
    __table_args__ = (UniqueConstraint("group_id", "phone_number"),)

    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), index=True)
    phone_number = Column(String, index=True, nullable=False)
    is_admin = Column(Boolean, default=False)
    joined_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_phone = Column(String, index=True, nullable=False)

    # Routing — exactly one of these is set
    receiver_phone = Column(String, index=True, nullable=True)   # DM
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="SET NULL"), index=True, nullable=True)

    content = Column(Text, nullable=False)
    message_type = Column(String, default="text")   # text | image | audio | file

    is_read = Column(Boolean, default=False)
    is_deleted = Column(Boolean, default=False)
    edited_at = Column(DateTime, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)