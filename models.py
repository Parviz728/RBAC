from pydantic import BaseModel

class Person(BaseModel):
    username: str
    password: str
    role: str