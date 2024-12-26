from pydantic import BaseModel

class LoginData(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    role_id: int
    role: str
    name: str
    no_of_role: int

class Validate(BaseModel):
    status:bool=True
    role_name:str
    id:int