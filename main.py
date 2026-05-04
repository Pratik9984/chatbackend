import os
import json
import random
import platform
import time
import uuid
import math
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Optional

import jwt
from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect,
    Depends, HTTPException, status, File, UploadFile, Request
)
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

if os.name == "nt":
    platform.machine = lambda: os.getenv("PROCESSOR_ARCHITECTURE", "AMD64")

from sqlalchemy import and_, delete, or_, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from database import AsyncSessionLocal, Base, engine, get_db
from models import Contact, Group, GroupMember, Message, User

# Config
SECRET_KEY = os.getenv("SECRET_KEY", "REPLACE_ME_IN_PRODUCTION")
ALGORITHM = "HS256"
TOKEN_EXPIRE_DAYS = 30
OTP_TTL = 300           
OTP_MAX_ATTEMPTS = 3  
MAX_FILE_BYTES = 10 * 1024 * 1024   # 10 MB
PAGE_SIZE = 50

ALLOWED_MIME = {
    "image/jpeg": "jpg",
    "image/png":  "png",
    "image/gif":  "gif",
    "image/webp": "webp",
    "audio/webm": "webm",
    "audio/mp4":  "m4a",
    "video/mp4":  "mp4",
    "application/pdf": "pdf",
}

BASE_URL = os.getenv("BASE_URL", "https://chatbackend-46yy.onrender.com").rstrip("/")
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
ALLOWED_ORIGINS = [origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "*").split(",")]

# Lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield

# App & middleware
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Enterprise Chat API", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

security = HTTPBearer()

@app.get("/health", tags=["system"])
async def health():
    return {"status": "ok"}

# JWT helpers
def create_token(phone: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(days=TOKEN_EXPIRE_DAYS)
    return jwt.encode({"sub": phone, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)

def _decode(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        phone = payload.get("sub")
        if not phone:
            raise HTTPException(status_code=401, detail="Invalid token")
        return phone
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def current_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> str:
    return _decode(creds.credentials)

# In-memory OTP store  (swap for Redis in production)
_otp: dict[str, dict] = {}

# WebSocket connection manager
class Manager:
    def __init__(self):
        self._sockets: dict[str, WebSocket] = {}

    async def connect(self, ws: WebSocket, phone: str):
        await ws.accept()
        self._sockets[phone] = ws

    def disconnect(self, phone: str):
        self._sockets.pop(phone, None)

    def is_online(self, phone: str) -> bool:
        return phone in self._sockets

    async def send(self, phone: str, data: dict):
        ws = self._sockets.get(phone)
        if ws:
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                self.disconnect(phone)

    async def broadcast(self, phones: list[str], data: dict):
        for p in phones:
            await self.send(p, data)

manager = Manager()

# Auth
class OTPRequest(BaseModel):
    phone_number: str

class OTPVerify(BaseModel):
    phone_number: str
    otp: str

@app.post("/auth/send-otp", tags=["auth"])
@limiter.limit("5/minute")
async def send_otp(req: OTPRequest, request: Request):
    phone = req.phone_number.strip()
    if not phone:
        raise HTTPException(status_code=400, detail="Phone number required")

    entry = _otp.get(phone)
    if entry and entry["expires_at"] > time.time() and entry["attempts"] >= OTP_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many attempts — request a new OTP after 5 minutes")

    otp = str(random.randint(100000, 999999))
    _otp[phone] = {"otp": otp, "expires_at": time.time() + OTP_TTL, "attempts": 0}
    print(f"\n[OTP] {phone} → {otp}  (expires in 5 min)\n")
    return {"message": "OTP sent"}

@app.post("/auth/verify-otp", tags=["auth"])
@limiter.limit("10/minute")
async def verify_otp(req: OTPVerify, request: Request, db: AsyncSession = Depends(get_db)):
    phone = req.phone_number.strip()
    entry = _otp.get(phone)

    if not entry:
        raise HTTPException(status_code=400, detail="No OTP requested for this number")
    if time.time() > entry["expires_at"]:
        _otp.pop(phone, None)
        raise HTTPException(status_code=400, detail="OTP expired — request a new one")

    entry["attempts"] += 1
    if entry["attempts"] > OTP_MAX_ATTEMPTS:
        _otp.pop(phone, None)
        raise HTTPException(status_code=429, detail="Too many wrong attempts — request a new OTP")
    if entry["otp"] != req.otp.strip():
        raise HTTPException(status_code=400, detail="Incorrect OTP")

    _otp.pop(phone, None)

    result = await db.execute(select(User).where(User.phone_number == phone))
    user = result.scalars().first()
    if not user:
        user = User(phone_number=phone)
        db.add(user)
        await db.commit()
        await db.refresh(user)

    return {
        "access_token": create_token(phone),
        "token_type": "bearer",
        "user": {
            "phone_number": user.phone_number,
            "display_name": user.display_name,
            "avatar_url": user.avatar_url,
        },
    }

# ==========================================
# ADMIN DASHBOARD - OTPs
# ==========================================

@app.get("/admin/api/otps", tags=["admin"])
async def get_admin_otps():
    """Returns a list of currently active OTPs."""
    current_time = time.time()
    active_otps = []
    
    for phone, data in list(_otp.items()):
        if data["expires_at"] > current_time:
            remaining = int(data["expires_at"] - current_time)
            mins, secs = divmod(remaining, 60)
            
            active_otps.append({
                "phone": phone,
                "otp": data["otp"],
                "expires_in": f"{mins}m {secs}s",
                "attempts": data["attempts"]
            })
            
    return {"otps": active_otps}

@app.get("/admin", response_class=HTMLResponse, tags=["admin"])
async def admin_dashboard():
    """Serves the HTML Admin Dashboard for OTPs."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Dashboard - OTP Monitor</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f4f4f9; color: #333; margin: 0; padding: 20px; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            .header-flex { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #eee; margin-bottom: 20px; padding-bottom: 10px; }
            h1 { font-size: 24px; margin: 0; }
            .nav-link { color: #007bff; text-decoration: none; font-weight: 500; }
            .nav-link:hover { text-decoration: underline; }
            table { width: 100%; border-collapse: collapse; margin-top: 10px; }
            th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }
            th { background-color: #f8f9fa; font-weight: 600; }
            .otp-code { font-family: monospace; font-size: 1.2em; font-weight: bold; color: #d9534f; letter-spacing: 2px; }
            .empty-state { text-align: center; padding: 20px; color: #777; font-style: italic; }
            .badge { display: inline-block; padding: 4px 8px; font-size: 12px; border-radius: 12px; background: #e0e0e0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header-flex">
                <h1>Active OTPs</h1>
                <a href="/admin/files" class="nav-link">View Uploaded Files →</a>
            </div>
            <p>This page auto-refreshes every 2 seconds.</p>
            <table>
                <thead>
                    <tr>
                        <th>Phone Number</th>
                        <th>OTP</th>
                        <th>Expires In</th>
                        <th>Attempts</th>
                    </tr>
                </thead>
                <tbody id="otp-table-body">
                    <!-- Data injected via JS -->
                </tbody>
            </table>
        </div>

        <script>
            async function fetchOTPs() {
                try {
                    const response = await fetch('/admin/api/otps');
                    const data = await response.json();
                    const tbody = document.getElementById('otp-table-body');
                    
                    if (data.otps.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No active OTPs right now.</td></tr>';
                        return;
                    }

                    tbody.innerHTML = data.otps.map(item => `
                        <tr>
                            <td><strong>${item.phone}</strong></td>
                            <td class="otp-code">${item.otp}</td>
                            <td>${item.expires_in}</td>
                            <td><span class="badge">${item.attempts} / 3</span></td>
                        </tr>
                    `).join('');
                } catch (error) {
                    console.error('Failed to fetch OTPs:', error);
                }
            }

            fetchOTPs();
            setInterval(fetchOTPs, 2000);
        </script>
    </body>
    </html>
    """
    return html_content

# ==========================================
# ADMIN DASHBOARD - FILES
# ==========================================

def format_size(size_bytes):
    if size_bytes == 0:
        return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

@app.get("/admin/api/files", tags=["admin"])
async def get_admin_files():
    """Returns a list of all uploaded files."""
    files_data = []
    if os.path.exists(UPLOAD_DIR):
        for filename in os.listdir(UPLOAD_DIR):
            filepath = os.path.join(UPLOAD_DIR, filename)
            if os.path.isfile(filepath):
                stat = os.stat(filepath)
                size = format_size(stat.st_size)
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                
                ext = filename.split('.')[-1].lower() if '.' in filename else ''
                is_image = ext in ['jpg', 'jpeg', 'png', 'gif', 'webp']
                
                files_data.append({
                    "filename": filename,
                    "url": f"/uploads/{filename}", 
                    "size": size,
                    "uploaded_at": mtime,
                    "is_image": is_image,
                    "ext": ext.upper()
                })
    
    files_data.sort(key=lambda x: x["uploaded_at"], reverse=True)
    return {"files": files_data}

@app.get("/admin/files", response_class=HTMLResponse, tags=["admin"])
async def admin_files_dashboard():
    """Serves the HTML Admin Dashboard for uploaded files."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Dashboard - File Viewer</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f4f4f9; color: #333; margin: 0; padding: 20px; }
            .container { max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            .header-flex { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #eee; margin-bottom: 20px; padding-bottom: 10px; }
            h1 { font-size: 24px; margin: 0; }
            .nav-link { color: #007bff; text-decoration: none; font-weight: 500; }
            .nav-link:hover { text-decoration: underline; }
            table { width: 100%; border-collapse: collapse; margin-top: 10px; }
            th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; vertical-align: middle; }
            th { background-color: #f8f9fa; font-weight: 600; }
            .empty-state { text-align: center; padding: 40px; color: #777; font-style: italic; }
            .badge { display: inline-block; padding: 4px 8px; font-size: 12px; border-radius: 4px; background: #e0e0e0; font-weight: bold; }
            .badge-img { background: #d4edda; color: #155724; }
            .badge-pdf { background: #f8d7da; color: #721c24; }
            .badge-aud { background: #cce5ff; color: #004085; }
            .badge-vid { background: #fff3cd; color: #856404; }
            .preview-img { max-width: 60px; max-height: 60px; border-radius: 4px; object-fit: cover; border: 1px solid #ccc; }
            .action-btn { background: #007bff; color: white; padding: 6px 12px; text-decoration: none; border-radius: 4px; font-size: 14px; }
            .action-btn:hover { background: #0056b3; }
            .filename { word-break: break-all; font-family: monospace; font-size: 13px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header-flex">
                <h1>Uploaded Documents & Media</h1>
                <a href="/admin" class="nav-link">← Back to OTPs</a>
            </div>
            <table>
                <thead>
                    <tr>
                        <th width="80">Preview</th>
                        <th>File Info</th>
                        <th width="120">Size</th>
                        <th width="180">Uploaded At</th>
                        <th width="100">Action</th>
                    </tr>
                </thead>
                <tbody id="files-table-body">
                    <tr><td colspan="5" style="text-align:center;">Loading files...</td></tr>
                </tbody>
            </table>
        </div>

        <script>
            function getBadgeClass(ext) {
                if (['JPG', 'JPEG', 'PNG', 'GIF', 'WEBP'].includes(ext)) return 'badge-img';
                if (ext === 'PDF') return 'badge-pdf';
                if (['WEBM', 'M4A'].includes(ext)) return 'badge-aud';
                if (['MP4'].includes(ext)) return 'badge-vid';
                return '';
            }

            async function fetchFiles() {
                try {
                    const response = await fetch('/admin/api/files');
                    const data = await response.json();
                    const tbody = document.getElementById('files-table-body');
                    
                    if (data.files.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No files have been uploaded yet.</td></tr>';
                        return;
                    }

                    tbody.innerHTML = data.files.map(f => `
                        <tr>
                            <td>
                                ${f.is_image 
                                    ? `<a href="${f.url}" target="_blank"><img src="${f.url}" class="preview-img" alt="preview"/></a>` 
                                    : `<span class="badge ${getBadgeClass(f.ext)}">${f.ext}</span>`
                                }
                            </td>
                            <td class="filename">${f.filename}</td>
                            <td>${f.size}</td>
                            <td style="font-size: 14px; color: #555;">${f.uploaded_at}</td>
                            <td>
                                <a href="${f.url}" target="_blank" class="action-btn">View / Download</a>
                            </td>
                        </tr>
                    `).join('');
                } catch (error) {
                    console.error('Failed to fetch files:', error);
                    document.getElementById('files-table-body').innerHTML = '<tr><td colspan="5" class="empty-state" style="color:red;">Error loading files. Check console.</td></tr>';
                }
            }

            fetchFiles();
        </script>
    </body>
    </html>
    """
    return html_content


# ==========================================
# PROFILE & CONTACTS
# ==========================================

class ProfileUpdate(BaseModel):
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None

@app.get("/profile/me", tags=["profile"])
async def get_my_profile(phone: str = Depends(current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.phone_number == phone))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "phone_number": user.phone_number,
        "display_name": user.display_name,
        "avatar_url": user.avatar_url,
    }

@app.patch("/profile/me", tags=["profile"])
async def update_profile(
    req: ProfileUpdate,
    phone: str = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.phone_number == phone))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if req.display_name is not None:
        user.display_name = req.display_name
    if req.avatar_url is not None:
        user.avatar_url = req.avatar_url
    await db.commit()
    return {"message": "Profile updated"}

@app.get("/profile/{phone_number}", tags=["profile"])
async def get_profile(phone_number: str, _: str = Depends(current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.phone_number == phone_number))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "phone_number": user.phone_number,
        "display_name": user.display_name,
        "avatar_url": user.avatar_url,
        "is_online": manager.is_online(phone_number),
        "last_seen": user.last_seen.isoformat() if user.last_seen else None,
    }

class ContactAdd(BaseModel):
    contact_phone: str
    nickname: Optional[str] = None

@app.get("/contacts", tags=["contacts"])
async def list_contacts(phone: str = Depends(current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Contact).where(Contact.owner_phone == phone))
    rows = result.scalars().all()
    out = []
    for c in rows:
        u = (await db.execute(select(User).where(User.phone_number == c.contact_phone))).scalars().first()
        out.append({
            "phone_number": c.contact_phone,
            "nickname": c.nickname,
            "display_name": u.display_name if u else None,
            "avatar_url": u.avatar_url if u else None,
            "is_online": manager.is_online(c.contact_phone),
        })
    return out

@app.post("/contacts", status_code=201, tags=["contacts"])
async def add_contact(req: ContactAdd, phone: str = Depends(current_user), db: AsyncSession = Depends(get_db)):
    existing = (await db.execute(select(Contact).where(and_(Contact.owner_phone == phone, Contact.contact_phone == req.contact_phone)))).scalars().first()
    if existing:
        raise HTTPException(status_code=400, detail="Contact already exists")
    db.add(Contact(owner_phone=phone, contact_phone=req.contact_phone, nickname=req.nickname))
    await db.commit()
    return {"message": "Contact added"}

@app.delete("/contacts/{contact_phone}", tags=["contacts"])
async def remove_contact(contact_phone: str, phone: str = Depends(current_user), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(Contact).where(and_(Contact.owner_phone == phone, Contact.contact_phone == contact_phone)))
    await db.commit()
    return {"message": "Contact removed"}

# ==========================================
# GROUPS
# ==========================================

class GroupCreate(BaseModel):
    name: str
    members: list[str]
    description: Optional[str] = None

async def _assert_member(phone: str, group_id: int, db: AsyncSession):
    row = (await db.execute(select(GroupMember).where(and_(GroupMember.group_id == group_id, GroupMember.phone_number == phone)))).scalars().first()
    if not row:
        raise HTTPException(status_code=403, detail="Not a member of this group")
    return row

async def _assert_admin(phone: str, group_id: int, db: AsyncSession):
    row = await _assert_member(phone, group_id, db)
    if not row.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")

@app.post("/groups", status_code=201, tags=["groups"])
async def create_group(req: GroupCreate, phone: str = Depends(current_user), db: AsyncSession = Depends(get_db)):
    group = Group(name=req.name, created_by=phone, description=req.description)
    db.add(group)
    await db.flush()
    phones = set(req.members) | {phone}
    for p in phones:
        db.add(GroupMember(group_id=group.id, phone_number=p, is_admin=(p == phone)))
    await db.commit()
    await db.refresh(group)
    return {"id": group.id, "name": group.name}

@app.get("/groups", tags=["groups"])
async def list_groups(phone: str = Depends(current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Group).join(GroupMember, GroupMember.group_id == Group.id).where(GroupMember.phone_number == phone))
    groups = result.scalars().all()
    out = []
    for g in groups:
        members = (await db.execute(select(GroupMember).where(GroupMember.group_id == g.id))).scalars().all()
        out.append({
            "id": g.id,
            "name": g.name,
            "description": g.description,
            "created_by": g.created_by,
            "members": [{"phone": m.phone_number, "is_admin": m.is_admin} for m in members],
        })
    return out

@app.post("/groups/{group_id}/members", tags=["groups"])
async def add_member(group_id: int, phone_number: str, phone: str = Depends(current_user), db: AsyncSession = Depends(get_db)):
    await _assert_admin(phone, group_id, db)
    db.add(GroupMember(group_id=group_id, phone_number=phone_number))
    await db.commit()
    return {"message": "Member added"}

@app.delete("/groups/{group_id}/members/{phone_number}", tags=["groups"])
async def remove_member(group_id: int, phone_number: str, phone: str = Depends(current_user), db: AsyncSession = Depends(get_db)):
    if phone_number != phone:
        await _assert_admin(phone, group_id, db)
    await db.execute(delete(GroupMember).where(and_(GroupMember.group_id == group_id, GroupMember.phone_number == phone_number)))
    await db.commit()
    return {"message": "Member removed"}

# ==========================================
# MESSAGES
# ==========================================

def _serialize(m: Message) -> dict:
    return {
        "id": m.id,
        "type": "direct_message" if m.receiver_phone else "group_message",
        "user": m.sender_phone,
        "receiver_phone": m.receiver_phone,
        "group_id": m.group_id,
        "content": m.content,
        "message_type": m.message_type,
        "is_read": m.is_read,
        "is_deleted": m.is_deleted,
        "edited_at": m.edited_at.isoformat() if m.edited_at else None,
        "timestamp": m.timestamp.isoformat(),
    }

@app.get("/messages/direct/{target_phone}", tags=["messages"])
async def get_direct_messages(target_phone: str, before_id: Optional[int] = None, phone: str = Depends(current_user), db: AsyncSession = Depends(get_db)):
    q = select(Message).where(and_(Message.is_deleted == False, or_(and_(Message.sender_phone == phone, Message.receiver_phone == target_phone), and_(Message.sender_phone == target_phone, Message.receiver_phone == phone)))).order_by(Message.timestamp.desc()).limit(PAGE_SIZE)
    if before_id: q = q.where(Message.id < before_id)
    msgs = list(reversed((await db.execute(q)).scalars().all()))
    await db.execute(update(Message).where(and_(Message.sender_phone == target_phone, Message.receiver_phone == phone, Message.is_read == False)).values(is_read=True))
    await db.commit()
    return [_serialize(m) for m in msgs]

@app.get("/messages/group/{group_id}", tags=["messages"])
async def get_group_messages(group_id: int, before_id: Optional[int] = None, phone: str = Depends(current_user), db: AsyncSession = Depends(get_db)):
    await _assert_member(phone, group_id, db)
    q = select(Message).where(and_(Message.group_id == group_id, Message.is_deleted == False)).order_by(Message.timestamp.desc()).limit(PAGE_SIZE)
    if before_id: q = q.where(Message.id < before_id)
    msgs = list(reversed((await db.execute(q)).scalars().all()))
    return [_serialize(m) for m in msgs]

class MessageEdit(BaseModel):
    content: str

@app.patch("/messages/{message_id}", tags=["messages"])
async def edit_message(message_id: int, req: MessageEdit, phone: str = Depends(current_user), db: AsyncSession = Depends(get_db)):
    msg = (await db.execute(select(Message).where(Message.id == message_id))).scalars().first()
    if not msg: raise HTTPException(status_code=404, detail="Message not found")
    if msg.sender_phone != phone: raise HTTPException(status_code=403, detail="Cannot edit another user's message")
    msg.content = req.content
    msg.edited_at = datetime.now(timezone.utc)
    await db.commit()
    updated = _serialize(msg)
    updated["type"] = "message_edited"
    if msg.receiver_phone: await manager.send(msg.receiver_phone, updated)
    elif msg.group_id:
        members = (await db.execute(select(GroupMember).where(GroupMember.group_id == msg.group_id))).scalars().all()
        await manager.broadcast([m.phone_number for m in members], updated)
    return {"message": "Updated"}

@app.delete("/messages/{message_id}", tags=["messages"])
async def delete_message(message_id: int, phone: str = Depends(current_user), db: AsyncSession = Depends(get_db)):
    msg = (await db.execute(select(Message).where(Message.id == message_id))).scalars().first()
    if not msg: raise HTTPException(status_code=404, detail="Message not found")
    if msg.sender_phone != phone: raise HTTPException(status_code=403, detail="Cannot delete another user's message")
    msg.is_deleted = True
    await db.commit()
    deleted_notice = {"type": "message_deleted", "id": message_id, "group_id": msg.group_id}
    if msg.receiver_phone: await manager.send(msg.receiver_phone, deleted_notice)
    elif msg.group_id:
        members = (await db.execute(select(GroupMember).where(GroupMember.group_id == msg.group_id))).scalars().all()
        await manager.broadcast([m.phone_number for m in members], deleted_notice)
    return {"message": "Deleted"}

@app.post("/upload", tags=["files"])
async def upload_file(file: UploadFile = File(...), phone: str = Depends(current_user)):
    if file.content_type not in ALLOWED_MIME: raise HTTPException(status_code=400, detail=f"File type '{file.content_type}' is not allowed")
    data = await file.read()
    if len(data) > MAX_FILE_BYTES: raise HTTPException(status_code=413, detail="File exceeds 10 MB limit")
    ext = ALLOWED_MIME[file.content_type]
    filename = f"{uuid.uuid4()}.{ext}"
    with open(os.path.join(UPLOAD_DIR, filename), "wb") as f: f.write(data)
    return {"url": f"{BASE_URL}/uploads/{filename}", "content_type": file.content_type}

# ==========================================
# WEBSOCKET
# ==========================================

@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket, token: str):
    try:
        phone = _decode(token)
    except HTTPException:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(websocket, phone)

    async with AsyncSessionLocal() as db:
        watchers = [c.owner_phone for c in (await db.execute(select(Contact).where(Contact.contact_phone == phone))).scalars().all()]
    await manager.broadcast(watchers, {"type": "presence", "user": phone, "online": True})

    try:
        while True:
            raw = await websocket.receive_text()
            try: payload = json.loads(raw)
            except json.JSONDecodeError: continue

            kind = payload.get("type")

            if kind == "typing":
                target = payload.get("target_user")
                if target: await manager.send(target, {"type": "typing", "user": phone})

            elif kind == "direct_message":
                target = payload.get("target_user")
                content = (payload.get("content") or "").strip()
                msg_type = payload.get("message_type", "text")
                if not target or not content: continue
                async with AsyncSessionLocal() as db:
                    msg = Message(sender_phone=phone, receiver_phone=target, content=content, message_type=msg_type)
                    db.add(msg)
                    await db.commit()
                    await db.refresh(msg)
                out = _serialize(msg)
                await manager.send(target, out)
                await manager.send(phone, out)

            elif kind == "group_message":
                group_id = payload.get("group_id")
                content = (payload.get("content") or "").strip()
                msg_type = payload.get("message_type", "text")
                if not group_id or not content: continue
                async with AsyncSessionLocal() as db:
                    check = (await db.execute(select(GroupMember).where(and_(GroupMember.group_id == group_id, GroupMember.phone_number == phone)))).scalars().first()
                    if not check: continue
                    msg = Message(sender_phone=phone, group_id=group_id, content=content, message_type=msg_type)
                    db.add(msg)
                    group = (await db.execute(select(Group).where(Group.id == group_id))).scalars().first()
                    members = (await db.execute(select(GroupMember).where(GroupMember.group_id == group_id))).scalars().all()
                    await db.commit()
                    await db.refresh(msg)
                out = _serialize(msg)
                out["group_name"] = group.name if group else ""
                await manager.broadcast([m.phone_number for m in members], out)

            elif kind == "read_receipt":
                target = payload.get("target_user")
                if target:
                    async with AsyncSessionLocal() as db:
                        await db.execute(update(Message).where(and_(Message.sender_phone == target, Message.receiver_phone == phone, Message.is_read == False)).values(is_read=True))
                        await db.commit()
                    await manager.send(target, {"type": "read_receipt", "reader": phone})

            # ---- WebRTC Call Signaling ----
            elif kind in ["call_offer", "call_answer", "ice_candidate", "call_end", "call_reject"]:
                target = payload.get("target_user")
                if target and manager.is_online(target):
                    signal_payload = {"type": kind, "user": phone}
                    if "sdp" in payload: signal_payload["sdp"] = payload["sdp"]
                    if "candidate" in payload: signal_payload["candidate"] = payload["candidate"]
                    if "isVideo" in payload: signal_payload["isVideo"] = payload["isVideo"]
                    await manager.send(target, signal_payload)

    except WebSocketDisconnect:
        manager.disconnect(phone)
        async with AsyncSessionLocal() as db:
            user = (await db.execute(select(User).where(User.phone_number == phone))).scalars().first()
            if user:
                user.last_seen = datetime.now(timezone.utc)
                await db.commit()
        await manager.broadcast(watchers, {"type": "presence", "user": phone, "online": False})
