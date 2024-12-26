from sqlalchemy import Table, MetaData,Integer,INTEGER,Column,String,BigInteger,ForeignKey
from database import engine,Base
metadata = MetaData()
UserLogin = Table("mstr_login", metadata, autoload_with=engine)

class MstrLogin(Base):
    __tablename__ = "mstr_login"
    UnsignedInt = Integer()
    UnsignedInt = UnsignedInt.with_variant(
        INTEGER(),
        "mysql",
    )
    id = Column( UnsignedInt,primary_key=True, index=True)
    email=Column(String(200))
    password=Column(String(200))
    first_name=Column(String(200))
    last_name=Column(String(200))
    role_id=Column(UnsignedInt)
    contact_number=Column(BigInteger)

class MstrRole (Base):
    __tablename__="mstr_role"
    UnsignedInt = Integer()
    UnsignedInt = UnsignedInt.with_variant(
        INTEGER(),
        "mysql",
    )
    id = Column(UnsignedInt,primary_key=True, index=True)
    role_name=Column(String(200))


class MstrUser(Base):
    __tablename__ = 'mstr_user'
    login_id = Column(Integer,primary_key=True)
    user_type_id = Column(Integer)
    ref_id = Column(Integer)
    role_type = Column(String)
    department_id = Column(Integer)
    designation_id = Column(Integer)


