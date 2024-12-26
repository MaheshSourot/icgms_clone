
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base


SQLALCHEMY_DATABASE_URL="postgresql+psycopg2://trainee_icgms:traineesharajman6@192.168.1.210:5432/trainee_icgms"

engine=create_engine(SQLALCHEMY_DATABASE_URL,echo=True)

SessionLocal=sessionmaker(autocommit=False,autoflush=False,bind=engine)

Base=declarative_base()
