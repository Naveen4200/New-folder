from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DB_URL = "mysql+mysqlconnector://root@localhost/test"

engine = create_engine(SQLALCHEMY_DB_URL)
Sessionlocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def construct_base_url():
    host = "localhost"
    port = 8000
    return f"http://{host}:{port}"
