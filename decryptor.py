import sys
import base64
from config import Config
from Cryptodome.Cipher import AES

SALT_LEN = Config.SALT_LENGTH
IV_LEN = Config.IV_LENGTH
TAG_LEN = Config.TAG_LENGTH


def decrypt(password, cipher_text):
    decoded_cipher_byte = base64.b64decode(cipher_text)

    salt = decoded_cipher_byte[:SALT_LEN]
    iv = decoded_cipher_byte[SALT_LEN : SALT_LEN + IV_LEN]
    encrypted_message_byte = decoded_cipher_byte[SALT_LEN + IV_LEN : -TAG_LEN]
    tag = decoded_cipher_byte[-TAG_LEN:]

    secret = Config.get_secret_key(password, salt)

    cipher = AES.new(secret, AES.MODE_GCM, iv)

    decrypted_message_byte = cipher.decrypt_and_verify(encrypted_message_byte, tag)
    decrypted_message = decrypted_message_byte.decode("utf-8")
    return decrypted_message


def handle_exit():
    print("Usage: python decrypter.py <cipher_text>")
    sys.exit(1)


def main():
    if not (len(sys.argv) == 2):
        handle_exit()

    cipher_text = sys.argv[1]
    secret_key = Config.SECRET_KEY

    print("------ AES-GCM Decryption ------")
    print(decrypt(secret_key, cipher_text))


if __name__ == "__main__":
    main()
