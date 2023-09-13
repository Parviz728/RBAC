from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from auth import Auth
from typing import Annotated
from models import Person
app = FastAPI()

USER_DATA = {
    "admin": {"username": "admin", "password": "adminpass", "role": "admin"},
    "user": {"username": "user", "password": "userpass", "role": "user"},
    "guest": {"username": "guest", "password": "guestpass", "role": "guest"}
}

PERMISSIONS = {
    "admin": ["read_item", "update_item", "create_item", "delete_item"],
    "user": ["read_item", "write_item"],
    "guest": ["read_item"]
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
auth = Auth()

def get_user(username: str) -> Person:
    if username in USER_DATA:
        return Person(**USER_DATA[username])
    return None

def set_permission(user: Person):
    if user.role == "admin":
        return PERMISSIONS["admin"]
    if user.role == "user":
        return PERMISSIONS["user"]
    if user.role == "guest":
        return PERMISSIONS["guest"]

@app.post('/token/')
def login(user_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_from_db = get_user(user_data.username)
    if user_from_db is None or user_from_db.password != user_data.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid credentials",
                            headers={"WWW-Authenticate": "Bearer"})
    return {"access token": auth.create_jwt_token({"sub": user_from_db.username})}

@app.get("/protected_resource")
def do(token: str = Depends(oauth2_scheme)):
    auth.get_user_from_token(token)

@app.get('/role/')
def admin_role(current_user: str = Depends(auth.get_user_from_token)):
    person = get_user(current_user)
    if person.role == "admin":
        return {"we have admin with privilegues": set_permission(person)}
    elif person.role == "user":
        return {"we have user with privilegues": set_permission(person)}
    elif person.role == "guest":
        return {"we have guest with privilegues": set_permission(person)}
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                         detail="No such role"
                         )




