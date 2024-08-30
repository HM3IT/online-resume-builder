from sqlalchemy.orm import mapped_column, Mapped, relationship
from sqlalchemy import String, Boolean, Date, ForeignKey, UniqueConstraint, text, UUID
from typing import List
from enum import Enum
from db import Base
import uuid
from sqlalchemy.dialects.postgresql import ENUM

proficiency_enum = ENUM(
    "Beginner",
    "Intermediate",
    "Proficient",
    "Expert",
    name="proficiency",
    create_type=True, 
)

class Proficiency(Enum):
    BEGINNER = "Beginner"
    INTERMEDIATE = "Intermediate"
    PROFICIENT = "Proficient"
    EXPERT = "Expert"


 
class WorkExperience(Base):
    __tablename__ = "work_experience"
    id: Mapped[str] = mapped_column(primary_key=True, default=lambda: str(uuid.uuid4()))
    resume_id: Mapped[int] = mapped_column(ForeignKey("resume.id"))
    company_name: Mapped[str] = mapped_column(String(40), nullable=False)
    position: Mapped[str] = mapped_column(String(40), nullable=False)
    location: Mapped[str] = mapped_column(String(150))
    start_date: Mapped[Date] = mapped_column(Date)
    end_date: Mapped[Date] = mapped_column(Date, nullable= True)
    is_working: Mapped[bool] = mapped_column(Boolean)
    summary: Mapped[str] = mapped_column(nullable=True)

    resume: Mapped["Resume"] = relationship(back_populates="work_experiences")


class Education(Base):
    __tablename__ = "education"
    id: Mapped[str] = mapped_column(primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(40), nullable=False)
    location: Mapped[str] = mapped_column(String(150))
    resume_id: Mapped[int] = mapped_column(ForeignKey("resume.id"))
    degree: Mapped[str] = mapped_column(String(40), nullable=False)
    start_date: Mapped[Date] = mapped_column(Date)
    end_date: Mapped[Date] = mapped_column(Date, nullable= True)
    is_graduate: Mapped[bool] = mapped_column(Boolean)

    resume: Mapped["Resume"] = relationship(back_populates="educations")


class Skill(Base):
    __tablename__ = "skill"
    id: Mapped[str] = mapped_column(primary_key=True, default=lambda: str(uuid.uuid4()))
    resume_id: Mapped[int] = mapped_column(ForeignKey("resume.id"))
    name: Mapped[str] = mapped_column(String(30))
    proficiency: Mapped[Proficiency] = mapped_column(proficiency_enum)

    resume: Mapped["Resume"] = relationship(back_populates="skills")


class Address(Base):
    __tablename__ = "address"
    id: Mapped[str] = mapped_column(primary_key=True, default=lambda: str(uuid.uuid4()))
    city: Mapped[str] = mapped_column(String(40), nullable=False)
    country: Mapped[str] = mapped_column(String(40), nullable=False)

    # To ensure no duplicate addresses data
    __table_args__ = (
        UniqueConstraint('city', 'country', name='unique_city_country'),
    )

    resumes: Mapped[List["Resume"]] = relationship(
        back_populates="address"
    )
    
class Resume(Base):
    __tablename__ = "resume"
    id: Mapped[str] = mapped_column(primary_key=True, default=lambda: str(uuid.uuid4()))
    template_id: Mapped[int] = mapped_column(ForeignKey("template.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    username: Mapped[str] = mapped_column(String(40), nullable=False)
    profession: Mapped[str] = mapped_column(String(40), nullable=False)
    image_file_path:Mapped[str] = mapped_column(String(150), nullable=True)
    phone: Mapped[str] = mapped_column(String(40), nullable=False)
    email: Mapped[str] = mapped_column(String(40), nullable=False)
    address_id: Mapped[int] = mapped_column(ForeignKey("address.id"))
    address: Mapped["Address"] = relationship(
        back_populates="resumes"
    )

    work_experiences: Mapped[List[WorkExperience]] = relationship(
        back_populates="resume", cascade="all, delete-orphan"
    )
    educations: Mapped[List[Education]] = relationship(
        back_populates="resume", cascade="all, delete-orphan"
    )
    skills: Mapped[List[Skill]] = relationship(
        back_populates="resume", cascade="all, delete-orphan"
    )
    user: Mapped["User"] = relationship(back_populates="resumes")

class Template(Base):
    __tablename__ ="template"
    id: Mapped[str] = mapped_column(primary_key=True, default=lambda: str(uuid.uuid4()))
    name:Mapped[str] = mapped_column(String(40),nullable=False)
    template_file_path:Mapped[str] = mapped_column(String(150),nullable=False)
    
class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(30), nullable=False)
    email: Mapped[str] = mapped_column(String(100), nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    resumes: Mapped[List["Resume"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    def __init__(self, name: str, email: str, password: str, **kwargs):
        super().__init__(**kwargs)
        self.name = name
        self.email = email
        self.password = password

    def __repr__(self) -> str:
        return f"User(id={self.id}), name={self.name}, email={self.email})"
