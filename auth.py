from config import Config
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
import jwt
from passlib.context import CryptContext  # для хеширования пароля
import datetime

oauth2_scheme = OAuth2PasswordBearer("token")

class Auth():
    hasher = CryptContext(schemes=['bcrypt'])
    config = Config()

    def encode_password(self, password):
        return self.hasher.hash(password + self.config.salt)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return self.hasher.verify(plain_password + self.config.salt, hashed_password)

    def create_jwt_token(self, data: dict):
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
        data.setdefault("exp", expire)
        return jwt.encode(data, self.config.secret_key, self.config.ALGORITHM)

    def get_user_from_token(self, token: str = Depends(oauth2_scheme)) -> str:
        try:
            payload = jwt.decode(token, self.config.secret_key, algorithms=[self.config.ALGORITHM])
            return payload.get("sub")
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Token has expired",
                                headers={"WWW-Authenticate": "Bearer"})
        except jwt.InvalidTokenError:
            HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                          detail="Invalid token",
                          headers={"WWW-Authenticate": "Bearer"})

    

