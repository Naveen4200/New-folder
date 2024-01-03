from datetime import datetime, timedelta
from typing import Optional
import bcrypt
import jwt
from fastapi import HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import Column, String, Integer, Boolean, DateTime, TIMESTAMP, BIGINT
from sqlalchemy.sql import func
from auth.auth_handler import signJWT
from database import Base, Sessionlocal
from my_config import api_response, get_db


class LoginInput(BaseModel):
    email: str
    password: str


class ChangePassword(BaseModel):
    current_password: str
    new_password: str

    class Config:
        from_attributes = True


class UserCreate(BaseModel):
    name: str
    email: str
    password: str
    mobile: int

    class Config:
        from_attributes = True


class UpdateUser(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    mobile: Optional[int] = None


def generate_token(data):
    exp = datetime.utcnow() + timedelta(days=365)
    token_payload = {'user_id': data['emp_id'], 'exp': exp}
    token = jwt.encode(token_payload, 'cat_walking_on_the street', algorithm='HS256')
    return token, exp


class Users(Base):
    __tablename__ = "users"
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255))
    email = Column(String(255), unique=True)
    password = Column(String(255))
    mobile = Column(BIGINT, unique=True)

    is_deleted = Column(Boolean, server_default='0', nullable=False)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.current_timestamp())
    deleted_on = Column(DateTime)

    # #######################################################################################################################

    @staticmethod
    def register(data: dict, db: Sessionlocal):
        try:
            usr = Users(**data)
            usr.created_at = datetime.now()
            usr.password = bcrypt.hashpw(usr.password.encode('utf-8'), bcrypt.gensalt())
            if db.query(Users).filter(Users.email == usr.email).first():
                return HTTPException(status_code=400, detail="User email already exists")

            if (not str(usr.mobile).isdigit()) or (len(str(usr.mobile)) != 10):
                return HTTPException(status_code=400, detail="Invalid mobile number")
            db.add(usr)
            db.commit()
            response = api_response(200, message="User Created successfully")
            return response
        except Exception as e:
            db.rollback()
            return HTTPException(status_code=500, detail=str(e))

    # #######################################################################################################################

    @staticmethod
    def update_user(user_data: UpdateUser, user_id: int, db: Sessionlocal):
        try:
            db_user = db.query(Users).filter(Users.user_id == user_id, Users.is_deleted == 0).first()
            if db_user is None:
                return HTTPException(status_code=404, detail="Record not found")

            if db.query(Users).filter(Users.email == user_data.email).first():
                return HTTPException(status_code=400, detail="User email already exists")

            if (not str(user_data.mobile).isdigit()) or (len(str(user_data.mobile)) != 10):
                return HTTPException(status_code=400, detail="Invalid mobile number")

            hero_data = user_data.model_dump(exclude_unset=True)
            for key, value in hero_data.items():
                setattr(db_user, key, value)
                db.add(db_user)
            db.commit()
            response = api_response(200, message="User Data updated successfully")
            return response
        except Exception as e:
            return HTTPException(status_code=500, detail=str(e))

    # ########################################################################################################################

    @staticmethod
    def read_user(user_id: int = None, name: str = None, email: str = None, mobile: int = None, page_num: int = 1,
                  page_size: int = 20, db: Sessionlocal = Depends(get_db)):
        try:
            start = (page_num - 1) * page_size
            base_query = db.query(Users).filter(Users.is_deleted == 0)
            if name:
                base_query = base_query.filter(Users.name == name)

            if email:
                base_query = base_query.filter(Users.email == email)

            if mobile:
                base_query = base_query.filter(Users.mobile == mobile)

            if user_id:
                base_query = base_query.filter(Users.user_id == user_id)

            total_users = base_query.count()
            users_records = base_query.offset(start).limit(page_size).all()

            if users_records:
                response = api_response(data=users_records, count=len(users_records), total=total_users,
                                        status_code=200)

                return response
            return HTTPException(status_code=404, detail="No data found")
        except Exception as e:
            return HTTPException(status_code=500, detail=f"Error: {str(e)}")

    # ------------------------------------------------------------------------------------------------------------------------------
    @staticmethod
    def user_delete(user_id: int, db: Sessionlocal):
        try:
            usr = db.query(Users).filter(Users.user_id == user_id,
                                         Users.is_deleted == 0).first()
            if usr is None:
                return HTTPException(status_code=404, detail=f"Record with id {user_id} not found")

            usr.is_deleted = True
            usr.deleted_on = datetime.now()

            db.commit()
            response = api_response(200, message="User Data deleted successfully")
            return response
        except Exception as e:
            db.rollback()
            return HTTPException(status_code=500, detail=str(e))

    # ###############################################################################################################

    @staticmethod
    def login(credential: LoginInput):
        try:
            session = Sessionlocal()
            user = session.query(Users).filter(Users.email == credential.email,
                                               Users.is_deleted == 0).filter().first()
            if not user:
                return HTTPException(status_code=404, detail="Invalid email or password")

            if bcrypt.checkpw(credential.password.encode('utf-8'), user.password.encode('utf-8')):
                token, exp = signJWT(user.user_id)
                response = {
                    'token': token,
                    'exp': exp,
                    "user_id": user.user_id,
                    "user_name": user.name,
                    'email_id': user.email,
                    'user_password': user.password,
                    "created_at": user.created_at,
                    'updated_at': user.updated_at
                }

                return response
            else:
                return HTTPException(status_code=401, detail='Invalid email or password')

        except Exception as e:
            return HTTPException(status_code=500, detail=f"Error: {str(e)}")

    ###################################################################################################################

    @staticmethod
    def change_password(credential: ChangePassword, user_id: int, db: Sessionlocal):
        try:
            user = db.query(Users).filter(Users.user_id == user_id, Users.is_deleted == 0).first()

            if not user:
                return HTTPException(status_code=404, detail="user not found")

            if bcrypt.checkpw(credential.current_password.encode('utf-8'), user.password.encode('utf-8')) is not True:
                return {"message": "wrong password"}

            if bcrypt.checkpw(credential.current_password.encode('utf-8'), user.password.encode('utf-8')):
                hashed_new_password = bcrypt.hashpw(credential.new_password.encode('utf-8'), bcrypt.gensalt())

                user.password = hashed_new_password
                db.commit()

            response = api_response(200, message="Password changed successfully")
            return response

        except Exception as e:
            return HTTPException(status_code=500, detail=f"Error: {str(e)}")
