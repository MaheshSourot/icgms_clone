
from database import SessionLocal
from typing import Annotated
from sqlalchemy.orm import Session
from passlib .context import CryptContext
from fastapi import APIRouter,Depends,status,HTTPException,FastAPI
from models import MstrLogin,MstrRole,MstrUser
from sqlalchemy.sql import func
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from datetime import datetime,timedelta
from schemas import LoginData,Token,Validate
from jose import jwt,JWTError



SECRET_KEY = "25d170fcad76bcdfaf173aa97e24a1d95a200745abc5b06443e13c49e81c2ea3"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security = HTTPBearer()

def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()
    
db_dependency=Annotated[Session,Depends(get_db)]
router=APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@router.post('/get_count_user')
def get_count_user(get_count: LoginData, db: db_dependency):
    

    query = (
    db.query(
       MstrUser.user_type_id.label('role_id'),MstrUser.role_type.label('role_name')
    )
    .join(MstrLogin, MstrUser.login_id == MstrLogin.id)
    .join(MstrRole, MstrLogin.role_id == MstrRole.id)
    .filter(MstrLogin.email == get_count.email)).all()

    no_of_role = (
    db.query(
       MstrLogin,MstrRole,MstrUser
    )
    .join(MstrLogin, MstrUser.login_id == MstrLogin.id)
    .join(MstrRole, MstrLogin.role_id == MstrRole.id)
    .filter(MstrLogin.email == get_count.email)).count()

    return {"role":query,"role_id":"","no_of_role":no_of_role}
    

    

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire, "email": data["email"]})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(db:db_dependency,security: HTTPAuthorizationCredentials = Depends(security)): 
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token = security.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("email")
        password:str=payload.get("password")
        user_type_id:int=payload.get("user_type_id")
        if email is None or  password is None or user_type_id is None:
            raise credentials_exception
        token_data = LoginData(email=email,password=password)
    except JWTError:
        raise credentials_exception
    user = db.query(MstrLogin).filter(MstrLogin.email == token_data.email).first()
    if user is None:
        raise credentials_exception
    return user


active_tokens=set()
@router.post("/token/{user_type_id}",response_model=Token)
def access_token(db: db_dependency, user_type_id: int, user_login: LoginData):
    # Query user information
    user = db.query(
        MstrLogin.id, MstrLogin.password, MstrLogin.email,
        MstrLogin.first_name, MstrLogin.last_name,
        MstrLogin.role_id, MstrRole.role_name
    ).join(
        MstrRole, MstrLogin.role_id == MstrRole.id
    ).filter(
        MstrLogin.email == user_login.email,
        MstrLogin.role_id == user_type_id
    ).first()

    print("====================================")
    
    if not user or not pwd_context.verify(user_login.password,user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Count the number of roles the user is associated with
    role_count = db.query(func.count(MstrRole.id)).join(
        MstrLogin, MstrLogin.role_id == MstrLogin.id
    ).filter(
        MstrLogin.email == user_login.email
    ).scalar()

    print("====================================")
    no_of_role = (
    db.query(
       MstrLogin,MstrRole,MstrUser
    )
    .join(MstrLogin, MstrUser.login_id == MstrLogin.id)
    .join(MstrRole, MstrLogin.role_id == MstrRole.id)
    .filter(MstrLogin.email == user.email)).count()

    
    # Generate access token
    access_token = create_access_token(data={"email": user_login.email,"password":user_login.password,"user_type_id":user_type_id,"role_name":user.role_name}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

    
    active_tokens.add(access_token)
    # Construct response
    token = {
        "access_token": access_token,
        "token_type": "bearer",
        "role_id": user.role_id,
        "role": user.role_name,
        "name": f"{user.first_name} {user.last_name}",
        "no_of_role":no_of_role    # Include role count in the response
    }
    return Token(**token)



@router.post('/validate_role/{role_id}',status_code=status.HTTP_201_CREATED,response_model=Validate)
def validate_role(db:db_dependency,role_id:int,user=Depends(get_current_user)):
   
    data=db.query(MstrRole).filter(MstrRole.id==role_id).first()
    response={
        "status":"True",
        "role_name":data.role_name,
        "id":data.id
    }
    return Validate(**response)




def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    if token not in active_tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    return token

@router.post('/logout')
def sign_out(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    print(token)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        expires_at = datetime.fromtimestamp(payload.get("exp"))
        print(expires_at)
        if token not in active_tokens:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or already logged out token",
            )
        active_tokens.remove(token)
        return {"message": "Logged out successfully"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )


@router.post('/get_active_user_details')
def get_active_user_Details(db:db_dependency,user=Depends(get_current_user)):
    query = (
    db.query(
        MstrUser.login_id,
        MstrLogin.email,
        MstrUser.user_type_id,
        MstrUser.ref_id,
        MstrLogin.first_name,
        MstrLogin.last_name,
        MstrLogin.contact_number,
        MstrUser.role_type,
        MstrUser.department_id,
        MstrUser.designation_id,
        MstrRole.role_name,
    )
    .join(MstrLogin, MstrUser.login_id == MstrLogin.id)
    .join(MstrRole, MstrLogin.role_id == MstrRole.id)
    .filter(MstrLogin.email == user.email)
).first()

    return query    
