import os
import hashlib
from dotenv import load_dotenv

load_dotenv()


class Config:
    HASH_NAME = str(os.getenv("HASH_NAME"))
    IV_LENGTH = int(os.getenv("IV_LENGTH"))
    ITERATION_COUNT = int(os.getenv("ITERATION_COUNT"))
    KEY_LENGTH = int(os.getenv("KEY_LENGTH"))
    SALT_LENGTH = int(os.getenv("SALT_LENGTH"))
    SECRET_KEY = str(os.getenv("SECRET_KEY"))
    TAG_LENGTH = int(os.getenv("TAG_LENGTH"))

    @classmethod
    def get_secret_key(cls, password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            hash_name=cls.HASH_NAME,
            password=password.encode(),
            salt=salt,
            iterations=cls.ITERATION_COUNT,
            dklen=cls.KEY_LENGTH,
        )
