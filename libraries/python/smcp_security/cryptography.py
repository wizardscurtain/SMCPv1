"""Cryptographic Security Layer

Provides ChaCha20-Poly1305 encryption, Argon2 key derivation,
and secure key management for SMCP.
"""

import os
import secrets
import hashlib
import hmac
from typing import Dict, Any, Optional, Tuple, Union, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP384R1, generate_private_key, ECDH,
    EllipticCurvePrivateKey, EllipticCurvePublicKey
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import argon2
from argon2 import PasswordHasher
from argon2 import low_level as argon2_low

from .exceptions import CryptographicError


@dataclass
class CryptoConfig:
    """Configuration for cryptographic operations"""
    algorithm: str = "ChaCha20-Poly1305"
    key_size: int = 32          # 256 bits
    nonce_size: int = 12        # 96 bits for ChaCha20Poly1305
    tag_size: int = 16          # 128 bits
    key_rotation_interval: int = 86400  # 24 hours in seconds
    # Argon2 fields
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536  # 64 MB
    argon2_parallelism: int = 1
    argon2_hash_len: int = 32
    argon2_salt_len: int = 16


@dataclass
class EncryptionResult:
    """Result of encryption operation"""
    ciphertext: bytes
    nonce: bytes
    algorithm: str
    key_id: Optional[str] = None
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


@dataclass
class KeyMetadata:
    """Metadata for cryptographic keys"""
    key_id: str
    algorithm: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    usage_count: int = 0
    max_usage: Optional[int] = None
    is_active: bool = True


class SMCPCrypto:
    """Main cryptographic operations class"""

    def __init__(self, config: Optional[CryptoConfig] = None):
        self.config = config if config is not None else CryptoConfig()
        self.master_key: Optional[bytes] = None
        self.active_keys: Dict[str, bytes] = {}
        self.current_key_id: Optional[str] = None
        self.key_metadata: Dict[str, KeyMetadata] = {}
        # Maintain insertion order list for cleanup_old_keys
        self._key_insertion_order: List[str] = []

    # ------------------------------------------------------------------ #
    #  Master key / key management
    # ------------------------------------------------------------------ #

    def set_master_key(self, key: bytes) -> None:
        """Store master key and generate initial working key."""
        self.master_key = key
        self.rotate_keys()

    def rotate_keys(self) -> str:
        """Generate a new key, store it, update current_key_id, return new key_id."""
        new_key = self.generate_key()
        key_id = secrets.token_hex(16)
        self.active_keys[key_id] = new_key
        self.key_metadata[key_id] = KeyMetadata(
            key_id=key_id,
            algorithm=self.config.algorithm,
            created_at=datetime.utcnow(),
        )
        self._key_insertion_order.append(key_id)
        self.current_key_id = key_id
        return key_id

    def cleanup_old_keys(self, keep_count: int = 5) -> None:
        """Keep only the keep_count most recently added keys."""
        while len(self._key_insertion_order) > keep_count:
            oldest_id = self._key_insertion_order.pop(0)
            self.active_keys.pop(oldest_id, None)
            self.key_metadata.pop(oldest_id, None)

    def derive_key(self, purpose: str, salt: bytes) -> bytes:
        """Derive a deterministic key from the master key using HKDF."""
        if self.master_key is None:
            raise CryptographicError("No master key set for key derivation")
        info = purpose.encode("utf-8")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self.config.key_size,
            salt=salt,
            info=info,
            backend=default_backend(),
        )
        return hkdf.derive(self.master_key)

    # ------------------------------------------------------------------ #
    #  Random generation
    # ------------------------------------------------------------------ #

    def generate_key(self) -> bytes:
        return os.urandom(self.config.key_size)

    def generate_nonce(self) -> bytes:
        return os.urandom(self.config.nonce_size)

    def generate_random_bytes(self, n: int) -> bytes:
        return os.urandom(n)

    # ------------------------------------------------------------------ #
    #  Symmetric encryption / decryption
    # ------------------------------------------------------------------ #

    def encrypt(self, plaintext: bytes, key: bytes = None) -> Dict[str, Any]:
        """Encrypt with ChaCha20-Poly1305.

        Returns dict with keys: ciphertext, nonce, key_id.
        """
        if key is not None:
            # Caller-supplied key: generate a temporary key_id from its hash
            key_id = hashlib.sha256(key).hexdigest()[:32]
        elif self.current_key_id is not None:
            key_id = self.current_key_id
            key = self.active_keys[key_id]
        else:
            raise CryptographicError("No encryption key available")

        nonce = self.generate_nonce()
        try:
            cipher = ChaCha20Poly1305(key)
            ciphertext = cipher.encrypt(nonce, plaintext, None)
        except Exception as exc:
            raise CryptographicError(f"Encryption failed: {exc}") from exc

        return {"ciphertext": ciphertext, "nonce": nonce, "key_id": key_id}

    def decrypt(self, encrypted_data: Dict[str, Any], key: bytes = None) -> bytes:
        """Decrypt ChaCha20-Poly1305 ciphertext."""
        key_id = encrypted_data.get("key_id")
        nonce = encrypted_data["nonce"]
        ciphertext = encrypted_data["ciphertext"]

        if key is None:
            # Try to look up key by key_id
            if key_id in self.active_keys:
                key = self.active_keys[key_id]
            else:
                raise CryptographicError("Decryption failed: key not found")

        try:
            cipher = ChaCha20Poly1305(key)
            return cipher.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise CryptographicError(f"Decryption failed: {exc}") from exc

    # ------------------------------------------------------------------ #
    #  Hashing & HMAC
    # ------------------------------------------------------------------ #

    def hash_data(self, data: bytes) -> bytes:
        """SHA-256 hash."""
        return hashlib.sha256(data).digest()

    def generate_hmac(self, key: bytes, data: bytes) -> bytes:
        """HMAC-SHA256."""
        return hmac.new(key, data, hashlib.sha256).digest()

    def verify_hmac(self, key: bytes, data: bytes, hmac_value: bytes) -> bool:
        """Constant-time HMAC verification."""
        expected = self.generate_hmac(key, data)
        return hmac.compare_digest(expected, hmac_value)

    # ------------------------------------------------------------------ #
    #  Asymmetric / EC operations
    # ------------------------------------------------------------------ #

    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """Generate EC P-384 key pair. Returns (private_pem, public_pem)."""
        private_key = generate_private_key(SECP384R1(), default_backend())
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem, public_pem

    def sign_data(self, private_key_bytes: bytes, data: bytes) -> bytes:
        """ECDSA signature with SHA-256."""
        private_key = serialization.load_pem_private_key(
            private_key_bytes, password=None, backend=default_backend()
        )
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def verify_signature(
        self, public_key_bytes: bytes, data: bytes, signature: bytes
    ) -> bool:
        """Verify ECDSA signature."""
        public_key = serialization.load_pem_public_key(
            public_key_bytes, backend=default_backend()
        )
        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def key_exchange(
        self, private_key_bytes: bytes, peer_public_key_bytes: bytes
    ) -> bytes:
        """ECDH key exchange. Returns 32-byte derived shared secret."""
        private_key = serialization.load_pem_private_key(
            private_key_bytes, password=None, backend=default_backend()
        )
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key_bytes, backend=default_backend()
        )
        shared_key = private_key.exchange(ECDH(), peer_public_key)
        # Derive a 32-byte key from the raw shared secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"smcp-key-exchange",
            backend=default_backend(),
        )
        return hkdf.derive(shared_key)

    # ------------------------------------------------------------------ #
    #  Password hashing
    # ------------------------------------------------------------------ #

    def hash_password(self, password: str) -> str:
        """Hash password with Argon2id. Returns hash string starting with $argon2."""
        ph = PasswordHasher(
            time_cost=self.config.argon2_time_cost,
            memory_cost=self.config.argon2_memory_cost,
            parallelism=self.config.argon2_parallelism,
            hash_len=self.config.argon2_hash_len,
            salt_len=self.config.argon2_salt_len,
        )
        return ph.hash(password)

    def verify_password(self, password: str, hash_str: str) -> bool:
        """Verify password against Argon2 hash."""
        ph = PasswordHasher()
        try:
            ph.verify(hash_str, password)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    #  Utility
    # ------------------------------------------------------------------ #

    def secure_compare(self, a, b) -> bool:
        """Timing-safe comparison."""
        return hmac.compare_digest(a, b)

    def analyze_request(self, request_data: Dict[str, Any],
                         context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Crypto-layer request analysis hook.

        Validates that any encrypted payload fields are well-formed so the
        test harness can patch this method to simulate crypto failures.
        Returns a status dict; raises on malformed input.
        """
        encrypted = request_data.get("_encrypted_params")
        if encrypted is not None and not isinstance(encrypted, dict):
            raise CryptographicError("Malformed encrypted payload")
        return {"crypto_check": "ok"}

    def cleanup(self) -> None:
        """Securely wipe key material from memory."""
        self.active_keys.clear()
        self.key_metadata.clear()
        self._key_insertion_order.clear()
        self.master_key = None
        self.current_key_id = None


# --------------------------------------------------------------------------- #
#  Argon2KeyDerivation
# --------------------------------------------------------------------------- #

class Argon2KeyDerivation:
    """Argon2 key derivation for password hashing and key stretching"""

    def __init__(
        self,
        time_cost: int = 3,
        memory_cost: int = 65536,
        parallelism: int = 1,
        hash_length: int = 32,
        salt_length: int = 16,
    ):
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.hash_length = hash_length
        self.salt_length = salt_length

        self.hasher = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_length,
            salt_len=salt_length,
        )

    def generate_salt(self) -> bytes:
        return os.urandom(self.salt_length)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive key bytes from password + salt using Argon2id low-level API.

        Raises TypeError if password is None, ValueError if password is empty
        or salt is empty.
        """
        if password is None:
            raise TypeError("password must not be None")
        if password == "":
            raise ValueError("password must not be empty")
        if not salt:
            raise ValueError("salt must not be empty")

        password_bytes = password.encode("utf-8") if isinstance(password, str) else password

        return argon2_low.hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=self.hash_length,
            type=argon2.Type.ID,
        )

    def derive_key_with_salt(self, password: str) -> Dict[str, bytes]:
        """Derive key and auto-generate salt. Returns {"key": bytes, "salt": bytes}."""
        salt = self.generate_salt()
        key = self.derive_key(password, salt)
        return {"key": key, "salt": salt}

    def hash_password(self, password: str) -> str:
        """Hash password for storage. Returns $argon2... string."""
        if isinstance(password, bytes):
            password = password.decode("utf-8")
        return self.hasher.hash(password)

    def verify_password(self, password: str, hash_str: str) -> bool:
        """Verify password against stored hash."""
        if isinstance(password, bytes):
            password = password.decode("utf-8")
        try:
            self.hasher.verify(hash_str, password)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False
        except Exception:
            return False

    def check_needs_rehash(self, hash_string: str) -> bool:
        try:
            return self.hasher.check_needs_rehash(hash_string)
        except Exception:
            return True


# --------------------------------------------------------------------------- #
#  SMCPHashing  (stub — kept for import compatibility)
# --------------------------------------------------------------------------- #

class SMCPHashing:
    """Simple hashing utilities."""

    @staticmethod
    def sha256(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    @staticmethod
    def sha512(data: bytes) -> bytes:
        return hashlib.sha512(data).digest()


# --------------------------------------------------------------------------- #
#  Remaining helper classes kept for backwards compatibility
# --------------------------------------------------------------------------- #

class SecureRandom:
    """Cryptographically secure random number generation"""

    @staticmethod
    def generate_token(length: int = 32) -> str:
        return secrets.token_hex(length)

    @staticmethod
    def generate_bytes(length: int) -> bytes:
        return secrets.token_bytes(length)

    @staticmethod
    def generate_urlsafe_token(length: int = 32) -> str:
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_numeric_code(digits: int = 6) -> str:
        max_value = 10 ** digits
        code = secrets.randbelow(max_value)
        return f"{code:0{digits}d}"


class MessageAuthentication:
    """Message authentication using HMAC"""

    def __init__(self, key: bytes, algorithm: str = "sha256"):
        self.key = key
        self.algorithm = algorithm
        supported = {"sha256", "sha384", "sha512"}
        if algorithm not in supported:
            raise CryptographicError(f"Unsupported hash algorithm: {algorithm}")

    def sign_message(self, message: Union[str, bytes]) -> bytes:
        if isinstance(message, str):
            message = message.encode("utf-8")
        return hmac.new(self.key, message, getattr(hashlib, self.algorithm)).digest()

    def verify_signature(self, message: Union[str, bytes], signature: bytes) -> bool:
        try:
            expected = self.sign_message(message)
            return hmac.compare_digest(signature, expected)
        except Exception:
            return False

    def sign_and_encode(self, message: Union[str, bytes]) -> str:
        import base64
        return base64.b64encode(self.sign_message(message)).decode("ascii")

    def verify_encoded_signature(
        self, message: Union[str, bytes], encoded_signature: str
    ) -> bool:
        try:
            import base64
            return self.verify_signature(message, base64.b64decode(encoded_signature))
        except Exception:
            return False
