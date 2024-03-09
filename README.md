# AES-GCM Encryption and Decryption

This Python script demonstrates AES-GCM encryption and decryption using a randomly generated secret key. It leverages the `pycryptodomex` library for cryptographic operations and the `python-dotenv` library for handling environment variables.

## Prerequisites

- Python 3.12.2
- Install dependencies:

  ```bash
  pip install -r requirements.txt
  ```

## 1. Create a virtual environment (optional, but recommended)

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

## 2. Create a `.env` file in the project directory:

```env
HASH_NAME=SHA512
IV_LENGTH=12
ITERATION_COUNT=65535
KEY_LENGTH=32
SALT_LENGTH=16
TAG_LENGTH=16
SECRET_KEY=your_randomly_generated_secret_key
```

# Usage

## Encryption

Run the following command to encrypt a plain text:

```bash
python encryptor.py "YourPlainText"
```

Or if you just want to use the sample values:

```bash
python encryptor.py
```

## Decryption

Run the following command to decrypt a base64 encoded string:

```bash
python decryptor.py "YourCipherText"
```
