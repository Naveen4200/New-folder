from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from auth.auth_bearer import JWTBearer, get_user_id_from_token
from database import Sessionlocal, engine, Base
from model.users import UserCreate, UpdateUser, Users, LoginInput, ChangePassword
from my_config import get_db

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

user_ops = Users()

Base.metadata.create_all(bind=engine)


@app.post('/api/login')
def login(credential: LoginInput):
    return user_ops.login(credential)


@app.post("/api/insert/register")
async def register(data: UserCreate, db: Session = Depends(get_db)):
    return user_ops.register(data.model_dump(), db)


@app.put("/api/update/user", dependencies=[Depends(JWTBearer())])
def update_user(user_data: UpdateUser, user_id: int = Depends(get_user_id_from_token),
                db: Sessionlocal = Depends(get_db)):
    return user_ops.update_user(user_data, user_id, db)


@app.get("/api/read/user", dependencies=[Depends(JWTBearer())])
def read_user(user_id: int = None, name: str = None, email: str = None, mobile: int = None, page_num: int = 1,
              page_size: int = 20, db: Sessionlocal = Depends(get_db)):
    return user_ops.read_user(user_id, name, email, mobile, page_num, page_size, db)


@app.delete("/api/delete/user", dependencies=[Depends(JWTBearer())])
async def user_delete(user_id: int, db: Session = Depends(get_db)):
    return user_ops.user_delete(user_id, db)


@app.post('/api/update/change_password', dependencies=[Depends(JWTBearer())])
def change_password(credential: ChangePassword, user_id: int = Depends(get_user_id_from_token),
                    db: Sessionlocal = Depends(get_db)):
    return user_ops.change_password(credential, user_id, db)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, port=5000)
