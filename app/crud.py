from sqlalchemy.orm import Session
from . import models
from passlib.hash import bcrypt

def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

def create_user(db: Session, username: str, password: str, role: str):
    hashed = bcrypt.hash(password)
    user = models.User(username=username, password=hashed, role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def delete_user(db: Session, user_id: int):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user:
        db.delete(user)
        db.commit()
    return user

def list_users(db: Session):
    return db.query(models.User).all()

