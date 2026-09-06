"""HealthPass API: SQLite locally, Railway PostgreSQL when DATABASE_URL is set."""
import hashlib, hmac, os, secrets
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

local_db = Path(__file__).resolve().parent.parent / "healthpass.db"
raw_url = os.getenv("DATABASE_URL", f"sqlite:///{local_db.as_posix()}")
db_url = raw_url.replace("postgres://", "postgresql+psycopg://", 1).replace("postgresql://", "postgresql+psycopg://", 1) if raw_url.startswith("postgres") else raw_url
engine = create_engine(db_url, connect_args={"check_same_thread": False} if db_url.startswith("sqlite") else {}, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

class Base(DeclarativeBase): pass
class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    full_name: Mapped[str] = mapped_column(String(120)); email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(128)); password_salt: Mapped[str] = mapped_column(String(32)); created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
class Token(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True); user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True)); created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
class Profile(Base):
    __tablename__ = "patient_profiles"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    date_of_birth: Mapped[date | None] = mapped_column(nullable=True); blood_group: Mapped[str | None] = mapped_column(String(4), nullable=True)
    height_cm: Mapped[float | None] = mapped_column(Float, nullable=True); weight_kg: Mapped[float | None] = mapped_column(Float, nullable=True)
    emergency_contact_name: Mapped[str | None] = mapped_column(String(120), nullable=True); emergency_contact_phone: Mapped[str | None] = mapped_column(String(30), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
class HealthEvent(Base):
    __tablename__ = "health_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True); user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    event_type: Mapped[str] = mapped_column(String(50)); event_date: Mapped[date] = mapped_column(); notes: Mapped[str | None] = mapped_column(Text, nullable=True); created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
class MedicalRecord(Base):
    __tablename__ = "medical_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True); user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    category: Mapped[str] = mapped_column(String(20)); name: Mapped[str] = mapped_column(String(160)); details: Mapped[str | None] = mapped_column(Text, nullable=True); created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

class RegisterIn(BaseModel): full_name: str = Field(min_length=2, max_length=120); email: EmailStr; password: str = Field(min_length=8, max_length=128)
class LoginIn(BaseModel): email: EmailStr; password: str = Field(min_length=8, max_length=128)
class ProfileIn(BaseModel):
    date_of_birth: date | None = None; blood_group: str | None = Field(default=None, max_length=4); height_cm: float | None = Field(default=None, gt=0, lt=300); weight_kg: float | None = Field(default=None, gt=0, lt=600); emergency_contact_name: str | None = Field(default=None, max_length=120); emergency_contact_phone: str | None = Field(default=None, max_length=30)
class EventIn(BaseModel): event_type: str = Field(min_length=2, max_length=50); event_date: date; notes: str | None = Field(default=None, max_length=2000)
class RecordIn(BaseModel): name: str = Field(min_length=1, max_length=160); details: str | None = Field(default=None, max_length=1000)

app = FastAPI(title="HealthPass API", version="0.2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
def now(): return datetime.now(timezone.utc)
def db_session():
    db = SessionLocal()
    try: yield db
    finally: db.close()
DB = Annotated[Session, Depends(db_session)]
def hash_pw(password, salt): return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600000).hex()
def user_out(u): return {"id": u.id, "full_name": u.full_name, "email": u.email}
def profile_out(p): return {"user_id":p.user_id,"date_of_birth":p.date_of_birth,"blood_group":p.blood_group,"height_cm":p.height_cm,"weight_kg":p.weight_kg,"emergency_contact_name":p.emergency_contact_name,"emergency_contact_phone":p.emergency_contact_phone,"updated_at":p.updated_at}
def event_out(e): return {"id":e.id,"event_type":e.event_type,"event_date":e.event_date,"notes":e.notes,"created_at":e.created_at}
def record_out(r): return {"id":r.id,"category":r.category,"name":r.name,"details":r.details,"created_at":r.created_at}
@app.on_event("startup")
def init(): Base.metadata.create_all(engine)
def current_user(authorization: Annotated[str | None, Header()] = None, db: Session = Depends(db_session)):
    if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401, "Authentication required")
    hashed = hashlib.sha256(authorization[7:].encode()).hexdigest(); token = db.scalar(select(Token).where(Token.token_hash == hashed, Token.expires_at > now()))
    if not token or not (user := db.get(User, token.user_id)): raise HTTPException(401, "Session expired or invalid")
    return user
CurrentUser = Annotated[User, Depends(current_user)]
def issue_token(db, user_id):
    raw = secrets.token_urlsafe(32); db.add(Token(token_hash=hashlib.sha256(raw.encode()).hexdigest(), user_id=user_id, expires_at=now()+timedelta(days=7), created_at=now())); return raw
def category(value):
    if value not in {"allergies","conditions","medications"}: raise HTTPException(404,"Unknown record category")
    return value

@app.get("/health")
def health(): return {"status":"ok"}
@app.post("/api/v1/auth/register", status_code=201)
def register(body: RegisterIn, db: DB):
    email=str(body.email).lower()
    if db.scalar(select(User).where(User.email==email)): raise HTTPException(409,"An account already uses this email")
    salt=os.urandom(16).hex(); user=User(full_name=body.full_name.strip(),email=email,password_hash=hash_pw(body.password,salt),password_salt=salt,created_at=now()); db.add(user); db.flush(); db.add(Profile(user_id=user.id,updated_at=now())); token=issue_token(db,user.id); db.commit(); return {"access_token":token,"token_type":"bearer","user":user_out(user)}
@app.post("/api/v1/auth/login")
def login(body: LoginIn, db: DB):
    user=db.scalar(select(User).where(User.email==str(body.email).lower()))
    if not user or not hmac.compare_digest(user.password_hash,hash_pw(body.password,user.password_salt)): raise HTTPException(401,"Incorrect email or password")
    token=issue_token(db,user.id); db.commit(); return {"access_token":token,"token_type":"bearer","user":user_out(user)}
@app.post("/api/v1/auth/logout", status_code=204)
def logout(authorization: Annotated[str | None, Header()] = None, db: Session = Depends(db_session)):
    if authorization and authorization.startswith("Bearer "):
        token=db.get(Token,hashlib.sha256(authorization[7:].encode()).hexdigest())
        if token: db.delete(token); db.commit()
@app.get("/api/v1/patients/me")
def get_profile(user: CurrentUser, db: DB): return {"user":user_out(user),"profile":profile_out(db.get(Profile,user.id))}
@app.put("/api/v1/patients/me")
def put_profile(body: ProfileIn,user: CurrentUser,db: DB):
    data=body.model_dump(exclude_unset=True)
    if not data: raise HTTPException(400,"Provide at least one profile field")
    profile=db.get(Profile,user.id)
    for key,value in data.items(): setattr(profile,key,value)
    profile.updated_at=now(); db.commit(); return {"user":user_out(user),"profile":profile_out(profile)}
@app.get("/api/v1/health-events")
def get_events(user: CurrentUser,db: DB): return {"events":[event_out(x) for x in db.scalars(select(HealthEvent).where(HealthEvent.user_id==user.id).order_by(HealthEvent.event_date.desc(),HealthEvent.id.desc())).all()]}
@app.post("/api/v1/health-events",status_code=201)
def post_event(body: EventIn,user: CurrentUser,db: DB):
    item=HealthEvent(user_id=user.id,event_type=body.event_type,event_date=body.event_date,notes=body.notes,created_at=now()); db.add(item);db.commit();db.refresh(item);return {"event":event_out(item)}
@app.get("/api/v1/records/{kind}")
def get_records(kind: str,user: CurrentUser,db: DB):
    kind=category(kind); return {"records":[record_out(x) for x in db.scalars(select(MedicalRecord).where(MedicalRecord.user_id==user.id,MedicalRecord.category==kind).order_by(MedicalRecord.id.desc())).all()]}
@app.post("/api/v1/records/{kind}",status_code=201)
def post_record(kind: str,body: RecordIn,user: CurrentUser,db: DB):
    item=MedicalRecord(user_id=user.id,category=category(kind),name=body.name.strip(),details=body.details.strip() if body.details else None,created_at=now());db.add(item);db.commit();db.refresh(item);return {"record":record_out(item)}
@app.delete("/api/v1/records/{kind}/{record_id}",status_code=204)
def delete_record(kind: str,record_id: int,user: CurrentUser,db: DB):
    item=db.scalar(select(MedicalRecord).where(MedicalRecord.id==record_id,MedicalRecord.user_id==user.id,MedicalRecord.category==category(kind)))
    if not item: raise HTTPException(404,"Record not found")
    db.delete(item);db.commit()
