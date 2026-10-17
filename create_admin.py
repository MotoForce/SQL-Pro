"""Promote an existing user; run only through a trusted server shell."""
import sys
from sqlalchemy import select
from app.main import SessionLocal, User
if len(sys.argv) != 2:
    raise SystemExit('Usage: python -m app.create_admin email@example.com')
with SessionLocal() as db:
    user = db.scalar(select(User).where(User.email == sys.argv[1].strip().lower()))
    if not user: raise SystemExit('Account not found')
    user.is_admin = True
    db.commit()
    print('Administrator promoted')
