"""SQL Pro authentication service. Run behind TLS reverse proxy in production."""
import os, secrets, hashlib, time, re, hmac, base64
from datetime import datetime, timezone, timedelta
from pathlib import Path
import json
from contextlib import asynccontextmanager
from typing import Optional
from urllib.parse import urlsplit
from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import create_engine, String, DateTime, ForeignKey, select, func, delete, Boolean, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./sqlpro.db')
REDIS_URL = os.getenv('REDIS_URL', '')
ENV = os.getenv('APP_ENV', 'development')
COOKIE_SECURE = ENV == 'production'
SESSION_HOURS = 12
ALLOWED_ORIGINS = set(filter(None, os.getenv('ALLOWED_ORIGINS', 'http://localhost:8000,http://127.0.0.1:8000').split(',')))
if ENV == 'production' and (not DATABASE_URL.startswith('postgresql') or not REDIS_URL or not os.getenv('ALLOWED_ORIGINS')):
    raise RuntimeError('Production requires PostgreSQL, Redis and ALLOWED_ORIGINS')

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=10 if DATABASE_URL.startswith('postgresql') else 5)
SessionLocal = sessionmaker(engine, expire_on_commit=False)
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

class Base(DeclarativeBase): pass
class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
class CatalogApp(Base):
    __tablename__ = 'catalog_apps'
    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(65))
    url: Mapped[str] = mapped_column(String(2048))
    icon: Mapped[str] = mapped_column(String(20), default='🔗')
    category: Mapped[str] = mapped_column(String(35), default='Aplicativos')
    description: Mapped[str] = mapped_column(String(140), default='')
    tags_json: Mapped[str] = mapped_column(Text, default='[]')
    featured: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)

class UserGrant(Base):
    __tablename__ = 'user_grants'
    __table_args__ = (UniqueConstraint('user_id', 'app_id', name='uq_user_app_grant'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), index=True)
    app_id: Mapped[int] = mapped_column(ForeignKey('catalog_apps.id', ondelete='CASCADE'), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

class LoginSession(Base):
    __tablename__ = 'login_sessions'
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), index=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

redis_client = None
# Rate limits in Redis operate across instances; local fallback is development-only.
local_counts = {}

def utcnow(): return datetime.now(timezone.utc)
def sha(v: str): return hashlib.sha256(v.encode()).hexdigest()
def db_session():
    with SessionLocal() as db: yield db

def rate_limit(key: str, max_attempts: int, period: int):
    global redis_client
    if redis_client:
        try:
            count = redis_client.incr(key)
            if count == 1: redis_client.expire(key, period)
            if count > max_attempts: raise HTTPException(429, 'Muitas tentativas. Tente novamente mais tarde.')
            return
        except HTTPException: raise
        except Exception:
            if ENV == 'production': raise HTTPException(503, 'Serviço temporariamente indisponível')
    elif ENV == 'production': raise HTTPException(503, 'Limitador indisponível')
    now = time.monotonic()
    if len(local_counts) > 20000:
        local_counts.clear()  # development-only; not a distributed protection
    count, expiry = local_counts.get(key, (0, now + period))
    if now > expiry: count, expiry = 0, now + period
    count += 1
    local_counts[key] = (count, expiry)
    if count > max_attempts: raise HTTPException(429, 'Muitas tentativas. Tente novamente mais tarde.')

@asynccontextmanager
async def lifespan(app):
    global redis_client
    if REDIS_URL:
        import redis
        redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=2)
        redis_client.ping()
    if ENV != 'production': Base.metadata.create_all(engine)
    # Production schema should be managed by migration tooling, not automatic startup mutation.
    yield

app = FastAPI(title='SQL Pro', version='2.0.1', lifespan=lifespan, docs_url=None if ENV == 'production' else '/docs')

@app.middleware('http')
async def protections(request: Request, call_next):
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        origin = request.headers.get('origin')
        if origin and origin not in ALLOWED_ORIGINS:
            return Response('Origem não autorizada', status_code=403)
        if ENV == 'production' and not origin:
            return Response('Origin obrigatório', status_code=403)
        if request.headers.get('content-type','').split(';')[0] != 'application/json' and request.url.path.startswith('/api/'):
            return Response('Content-Type inválido', status_code=415)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Frame-Options'] = 'DENY'
    # Inline UI assets are hash-pinned rather than allowing arbitrary inline scripts.
    # This makes panel_sqlpro.html portable (file:// / content:// preview) without
    # lowering the CSP protection on other application routes.
    if request.url.path == '/panel':
        page = Path(__file__).with_name('panel_sqlpro.html').read_text(encoding='utf8')
        def inline_hash(tag):
            match = re.search(rf'<{tag}>(.*?)</{tag}>', page, flags=re.DOTALL)
            if not match:
                raise RuntimeError(f'Painel sem {tag} embutido')
            digest = hashlib.sha256(match.group(1).encode('utf8')).digest()
            return "'sha256-" + base64.b64encode(digest).decode('ascii') + "'"
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; style-src 'self' " + inline_hash('style') +
            "; img-src 'self' data:; script-src 'self' " + inline_hash('script') +
            "; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
    else:
        response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; img-src 'self' data:; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    response.headers['Cache-Control'] = 'no-store'
    if COOKIE_SECURE: response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)

def normalize_email(email): return email.strip().lower()
def ip(request):
    # Never trust X-Forwarded-For directly. Configure trusted proxies at deployment.
    return request.client.host if request.client else 'unknown'

def current(request: Request, db: Session = Depends(db_session)):
    token = request.cookies.get('sqlpro_session', '')
    if not token: raise HTTPException(401, 'Não autenticado')
    record = db.scalar(select(LoginSession).where(LoginSession.token_hash == sha(token)))
    if not record or record.expires_at.replace(tzinfo=timezone.utc) <= utcnow():
        raise HTTPException(401, 'Sessão expirada')
    user = db.get(User, record.user_id)
    if not user: raise HTTPException(401, 'Conta indisponível')
    return user, record

def grant_session(response: Response, user: User, db: Session):
    token = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)
    db.add(LoginSession(token_hash=sha(token), csrf_hash=sha(csrf), user_id=user.id, expires_at=utcnow()+timedelta(hours=SESSION_HOURS)))
    db.commit()
    response.set_cookie('sqlpro_session', token, max_age=SESSION_HOURS*3600, httponly=True, secure=COOKIE_SECURE, samesite='strict', path='/')
    return csrf

@app.post('/api/register', status_code=201)
def register(data: Credentials, request: Request, response: Response, db: Session = Depends(db_session)):
    rate_limit('register:'+ip(request), 8, 3600)
    email = normalize_email(str(data.email))
    if db.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(409, 'Não foi possível criar esta conta')
    user = User(email=email, password_hash=ph.hash(data.password))
    db.add(user)
    try: db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(409, 'Não foi possível criar esta conta')
    db.refresh(user)
    csrf = grant_session(response, user, db)
    return {'user': {'email': user.email, 'admin': False}, 'csrf': csrf}

@app.post('/api/login')
def login(data: Credentials, request: Request, response: Response, db: Session = Depends(db_session)):
    email = normalize_email(str(data.email))
    rate_limit('login-ip:'+ip(request), 30, 900)
    rate_limit('login-user:'+sha(email), 10, 900)
    user = db.scalar(select(User).where(User.email == email))
    try:
        verified = ph.verify(user.password_hash if user else DUMMY_HASH, data.password)
    except (VerifyMismatchError, VerificationError): verified = False
    if not user or not verified: raise HTTPException(401, 'Credenciais inválidas')
    if ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(data.password)
        db.commit()
    csrf = grant_session(response, user, db)
    return {'user': {'email': user.email, 'admin': user.is_admin}, 'csrf': csrf}

DUMMY_HASH = ph.hash('not-a-valid-real-user-password-902374')

@app.get('/api/me')
def me(auth=Depends(current)):
    user, _ = auth
    return {'email': user.email, 'admin': user.is_admin}

@app.get('/api/csrf')
def get_csrf(auth=Depends(current), db: Session = Depends(db_session)):
    user, session = auth
    csrf = secrets.token_urlsafe(32)
    session.csrf_hash = sha(csrf)
    db.commit()
    return {'csrf': csrf}

def require_csrf(request: Request, auth=Depends(current)):
    _, session = auth
    supplied = request.headers.get('x-csrf-token','')
    if not supplied or not hmac.compare_digest(sha(supplied), session.csrf_hash):
        raise HTTPException(403, 'Token CSRF inválido')
    return auth

@app.post('/api/logout')
def logout(request: Request, response: Response, db: Session = Depends(db_session), auth=Depends(require_csrf)):
    _, session = auth
    db.delete(session); db.commit()
    response.delete_cookie('sqlpro_session', path='/', secure=COOKIE_SECURE, httponly=True, samesite='strict')
    return {'ok': True}

@app.get('/api/admin/stats')
def admin_stats(auth=Depends(current), db: Session = Depends(db_session)):
    user, _ = auth
    if not user.is_admin: raise HTTPException(403, 'Acesso restrito')
    return {'users': db.scalar(select(func.count()).select_from(User)), 'active_sessions': db.scalar(select(func.count()).select_from(LoginSession).where(LoginSession.expires_at > utcnow()))}

@app.get('/api/health')
def health(db: Session = Depends(db_session)):
    db.execute(select(1))
    return {'status': 'ok'}

@app.get('/')
def home(): return FileResponse(Path(__file__).with_name('index.html'))
@app.get('/static/app.js')
def frontend_js(): return FileResponse(Path(__file__).with_name('app.js'), media_type='text/javascript')
@app.get('/static/style.css')
def frontend_css(): return FileResponse(Path(__file__).with_name('style.css'), media_type='text/css')


# SQL Pro 2.0: central application entitlements for the Lima Virtual portal.
class ApplicationPayload(BaseModel):
    slug: str = Field(pattern=r'^[a-z0-9][a-z0-9_-]{0,79}$')
    name: str = Field(min_length=1, max_length=65)
    url: str = Field(min_length=12, max_length=2048)
    icon: str = Field(default='🔗', max_length=20)
    category: str = Field(default='Aplicativos', min_length=1, max_length=35)
    description: str = Field(default='', max_length=140)
    tags: list[str] = Field(default_factory=list, max_length=12)
    featured: bool = False
    active: bool = True

    @field_validator('url')
    @classmethod
    def secure_https_url(cls, value):
        parsed = urlsplit(value)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or any(x in value for x in ('\r','\n')):
            raise ValueError('Informe um link HTTPS válido sem credenciais')
        return value

class GrantPayload(BaseModel):
    email: EmailStr
    slug: str = Field(pattern=r'^[a-z0-9][a-z0-9_-]{0,79}$')
    active: bool = True
    expires_at: Optional[datetime] = None

def require_admin(auth=Depends(current)):
    user, _ = auth
    if not user.is_admin:
        raise HTTPException(403, 'Acesso administrativo restrito')
    return auth

def require_admin_write(auth=Depends(require_csrf)):
    user, _ = auth
    if not user.is_admin:
        raise HTTPException(403, 'Acesso administrativo restrito')
    return auth

def app_dict(a: CatalogApp):
    return {'id': a.slug, 'name': a.name, 'url': a.url, 'icon': a.icon, 'category': a.category,
            'description': a.description, 'tags': json.loads(a.tags_json), 'featured': a.featured, 'active': a.active}

def licensed_grant(db: Session, user: User, slug: str):
    return db.execute(select(CatalogApp, UserGrant)
        .join(UserGrant, UserGrant.app_id == CatalogApp.id)
        .where(CatalogApp.slug == slug, CatalogApp.active == True,
               UserGrant.user_id == user.id, UserGrant.active == True,
               (UserGrant.expires_at == None) | (UserGrant.expires_at > utcnow()))).first()

@app.get('/api/portal/apps')
def portal_apps(auth=Depends(current), db: Session = Depends(db_session)):
    user, _ = auth
    rows = db.execute(select(CatalogApp)
        .join(UserGrant, UserGrant.app_id == CatalogApp.id)
        .where(CatalogApp.active == True, UserGrant.active == True,
               UserGrant.user_id == user.id,
               (UserGrant.expires_at == None) | (UserGrant.expires_at > utcnow()))
        .order_by(CatalogApp.name)).scalars().all()
    return [app_dict(a) for a in rows]

@app.get('/api/portal/launch/{slug}')
def portal_launch(slug: str, auth=Depends(current), db: Session = Depends(db_session)):
    user, _ = auth
    grant = licensed_grant(db, user, slug)
    if not grant: raise HTTPException(403, 'Aplicativo não autorizado ou licença expirada')
    # Redirect checks access *on every launch*; the destination app must independently
    # verify identity if it is hosted as a publicly accessible static website.
    return RedirectResponse(grant[0].url, status_code=302)

@app.get('/api/admin/apps')
def list_catalog(auth=Depends(require_admin), db: Session = Depends(db_session)):
    return [app_dict(a) for a in db.scalars(select(CatalogApp).order_by(CatalogApp.name)).all()]

@app.post('/api/admin/apps', status_code=201)
def upsert_app(data: ApplicationPayload, auth=Depends(require_admin_write), db: Session = Depends(db_session)):
    a = db.scalar(select(CatalogApp).where(CatalogApp.slug == data.slug))
    if not a:
        a = CatalogApp(slug=data.slug)
        db.add(a)
    for field in ('name','url','icon','category','description','featured','active'):
        setattr(a, field, getattr(data, field))
    a.tags_json = json.dumps([tag[:35] for tag in data.tags], ensure_ascii=False)
    db.commit()
    return app_dict(a)

@app.post('/api/admin/grants')
def set_grant(data: GrantPayload, auth=Depends(require_admin_write), db: Session = Depends(db_session)):
    user = db.scalar(select(User).where(User.email == normalize_email(str(data.email))))
    a = db.scalar(select(CatalogApp).where(CatalogApp.slug == data.slug))
    if not user or not a: raise HTTPException(404, 'Conta ou aplicativo não encontrado')
    if data.expires_at and (data.expires_at.tzinfo is None or data.expires_at.utcoffset() is None):
        raise HTTPException(422, 'Validade deve conter fuso horário')
    grant = db.scalar(select(UserGrant).where(UserGrant.user_id == user.id, UserGrant.app_id == a.id))
    if not grant:
        grant = UserGrant(user_id=user.id, app_id=a.id)
        db.add(grant)
    grant.active = data.active
    grant.expires_at = data.expires_at
    db.commit()
    return {'ok': True, 'user_email': user.email, 'slug': a.slug, 'active': grant.active,
            'expires_at': grant.expires_at.isoformat() if grant.expires_at else None}

@app.get('/api/admin/grants')
def list_grants(auth=Depends(require_admin), db: Session = Depends(db_session)):
    rows = db.execute(select(User.email, CatalogApp.slug, UserGrant.active, UserGrant.expires_at)
        .join(User, User.id == UserGrant.user_id)
        .join(CatalogApp, CatalogApp.id == UserGrant.app_id).order_by(User.email, CatalogApp.slug)).all()
    return [{'email': row[0], 'slug': row[1], 'active': row[2],
             'expires_at': row[3].isoformat() if row[3] else None} for row in rows]

@app.get('/panel')
def panel_ui(auth=Depends(current)):
    # Served only after authenticating the session; sensitive
    # operations are enforced by SQL Pro's server-side authentication.
    return FileResponse(Path(__file__).with_name('panel_sqlpro.html'), media_type='text/html')

@app.get('/api/admin/users')
def admin_users(auth=Depends(require_admin), db: Session = Depends(db_session)):
    rows = db.scalars(select(User).order_by(User.id.desc()).limit(200)).all()
    return [{'email': u.email, 'admin': u.is_admin} for u in rows]

@app.get('/static/panel.css')
def panel_css(): return FileResponse(Path(__file__).with_name('panel.css'), media_type='text/css')
@app.get('/static/panel.js')
def panel_js(): return FileResponse(Path(__file__).with_name('panel.js'), media_type='text/javascript')
