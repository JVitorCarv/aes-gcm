import sys
import base64
from config import Config
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


def encrypt(password: str, plain_message: str) -> str:
    salt: bytes = get_random_bytes(Config.SALT_LENGTH)
    iv: bytes = get_random_bytes(Config.IV_LENGTH)

    secret: bytes = Config.get_secret_key(password, salt)

    cipher = AES.new(secret, AES.MODE_GCM, iv)

    encrypted_message_byte, tag = cipher.encrypt_and_digest(
        plain_message.encode("utf-8")
    )
    cipher_byte: bytes = salt + iv + encrypted_message_byte + tag

    encoded_cipher_byte: bytes = base64.b64encode(cipher_byte)
    return bytes.decode(encoded_cipher_byte)


def print_usage_and_exit() -> None:
    print("Usage: python script.py <plain_text>")
    sys.exit(1)


def main():
    secret_key = Config.SECRET_KEY
    if len(sys.argv) < 1 or len(sys.argv) > 2:
        print_usage_and_exit()

    elif len(sys.argv) == 1:
        plain_text = "CESAR School"

    else:
        plain_text = sys.argv[1]

    print("------ AES-GCM Encryption ------")
    print(f"plain: {plain_text}")
    print(f"encrypted: {encrypt(secret_key, plain_text)}")


if __name__ == "__main__":
    main()
