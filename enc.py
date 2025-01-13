import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# --- Core Encryption and Decryption Functions ---

def encrypt(key, data):
    """
    Encrypts the given data using AES-GCM with the provided key.
    :param key: 32-byte encryption key
    :param data: Data to encrypt (bytes)
    :return: Base64-encoded string containing nonce, tag, and ciphertext
    """
    if len(key) != 32:
        raise ValueError("Key length must be 32 bytes.")

    try:
        nonce = secrets.token_bytes(12)  # Secure random nonce
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag

        # Concatenate nonce, tag, and ciphertext, and encode in Base64
        return base64.b64encode(nonce + tag + ciphertext).decode('utf-8')
    except Exception as e:
        raise RuntimeError(f"Encryption error: {str(e)}") from e


def decrypt(key, encrypted_data):
    """
    Decrypts the Base64-encoded encrypted data using AES-GCM with the provided key.
    :param key: 32-byte decryption key
    :param encrypted_data: Base64-encoded string containing nonce, tag, and ciphertext
    :return: Decrypted data (bytes)
    """
    if len(key) != 32:
        raise ValueError("Key length must be 32 bytes.")

    try:
        decoded_data = base64.b64decode(encrypted_data)
        if len(decoded_data) < 28:
            raise ValueError("Insufficient data length for nonce, tag, and ciphertext.")

        nonce = decoded_data[:12]
        tag = decoded_data[12:28]
        ciphertext = decoded_data[28:]

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        raise RuntimeError(f"Decryption error: {str(e)}") from e


# --- Helper Functions for Key and Salt Generation ---

def generate_key():
    """
    Generates a 32-byte cryptographically secure encryption key.
    :return: Key (bytes)
    """
    return secrets.token_bytes(32)


def generate_salt(length=16):
    """
    Generates a random cryptographic salt of the specified length.
    :param length: Length of the salt in bytes
    :return: Salt (bytes)
    """
    if length <= 0:
        raise ValueError("Salt length must be positive.")
    return secrets.token_bytes(length)


def hash_string(data, salt, iterations=100000):
    """
    Hashes the given data using PBKDF2 with SHA256.
    :param data: Data to hash (bytes)
    :param salt: Cryptographic salt (bytes)
    :param iterations: Number of iterations for the key derivation
    :return: Derived key (bytes)
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(data)


# --- Validation Functions ---

def validate_key(key):
    """
    Validates whether the key is a 32-byte value.
    :param key: Encryption key to validate
    :return: None (raises ValueError if invalid)
    """
    if not isinstance(key, bytes):
        raise ValueError("Key must be bytes.")
    if len(key) != 32:
        raise ValueError("Key length must be exactly 32 bytes.")


# --- Expanded Test Suite ---

def test_encryption():
    try:
        test_key = generate_key()
        test_data = "Sensitive information".encode('utf-8')
        encrypted_data = encrypt(test_key, test_data)
        decrypted_data = decrypt(test_key, encrypted_data)

        assert decrypted_data == test_data, "Decrypted data does not match original."
        return True, "Encryption and decryption tests passed."
    except Exception as e:
        return False, f"Encryption test failed: {str(e)}"


def test_decryption_with_invalid_data():
    try:
        test_key = generate_key()
        invalid_encrypted_data = "InvalidEncryptedData"
        decrypt(test_key, invalid_encrypted_data)  # Should raise an error
        return False, "Decryption with invalid data should have failed."
    except Exception as e:
        return True, f"Decryption with invalid data failed as expected: {str(e)}"


def test_key_validation():
    try:
        valid_key = generate_key()
        validate_key(valid_key)  # Should pass without errors
        
        invalid_key = secrets.token_bytes(16)  # Invalid key length (16 bytes)
        try:
            validate_key(invalid_key)
            return False, "Key validation should have failed for invalid key."
        except ValueError as e:
            return True, f"Key validation failed as expected: {str(e)}"
    except Exception as e:
        return False, f"Key validation test failed: {str(e)}"


def test_salt_generation():
    try:
        salt = generate_salt(16)
        assert len(salt) == 16, "Salt length mismatch."
        salt_empty = generate_salt(0)  # Should raise an error
        return False, "Salt length 0 should have raised an error."
    except ValueError:
        return True, "Salt generation test passed."
    except Exception as e:
        return False, f"Salt generation test failed: {str(e)}"


def test_hashing():
    try:
        salt = generate_salt(16)
        data = "password123".encode('utf-8')
        hashed_data = hash_string(data, salt)
        assert len(hashed_data) == 32, "Hash length mismatch."
        
        # Test hashing with incorrect salt length
        try:
            generate_salt(-1)  # Should raise an error
            return False, "Negative salt length should have raised an error."
        except ValueError:
            return True, "Hashing test passed."
    except Exception as e:
        return False, f"Hashing test failed: {str(e)}"


def test_edge_cases():
    # Test encryption with an empty string
    try:
        test_key = generate_key()
        encrypted_data = encrypt(test_key, b"")
        decrypted_data = decrypt(test_key, encrypted_data)
        assert decrypted_data == b"", "Decrypted empty string does not match."
        return True, "Edge case test for empty string passed."
    except Exception as e:
        return False, f"Edge case test for empty string failed: {str(e)}"


def test_all():
    tests = [
        ("Encryption Test", test_encryption),
        ("Decryption with Invalid Data", test_decryption_with_invalid_data),
        ("Key Validation Test", test_key_validation),
        ("Salt Generation Test", test_salt_generation),
        ("Hashing Test", test_hashing),
        ("Edge Case Test (Empty String)", test_edge_cases)
    ]

    for name, test in tests:
        result, message = test()
        status = "PASS" if result else "FAIL"
        print(f"{name}: {status} - {message}")


# --- Example Usage ---

if __name__ == "__main__":
    print("Running all tests...")
    test_all()
