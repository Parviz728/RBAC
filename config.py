import os
from dotenv import load_dotenv

load_dotenv()
class Config():
    secret_key = os.getenv("SECRET_KEY")
    ALGORITHM = os.getenv("ALGORITHM")
    salt = "salt#_#"
    EXP_MINUTES = 10
