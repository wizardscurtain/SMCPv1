"""Cryptographic Security Layer

Provides ChaCha20-Poly1305 encryption, Argon2 key derivation,
and secure key management for SMCP.
"""

import os
import secrets
import hashlib
import hmac
from typing import Dict, Any, Optional, Tuple, Union, List
from dataclasses import dataclass
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import argon2

from .exceptions import CryptographicError


@dataclass
class CryptoConfig:
    """Configuration for cryptographic operations"""
    key_size: int = 32  # 256 bits
    nonce_size: int = 12  # 96 bits for ChaCha20Poly1305
    default_key_expiry_hours: int = 24
    max_key_usage: Optional[int] = None
    enable_key_rotation: bool = True
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
        if config is not None:
            self.config = config
            self.key_size = config.key_size
            self.nonce_size = config.nonce_size
        else:
            self.config = CryptoConfig()
            self.key_size = 32  # 256 bits for ChaCha20
            self.nonce_size = 12  # 96 bits for ChaCha20Poly1305
        self.active_keys: Dict[str, bytes] = {}
        self.key_metadata: Dict[str, KeyMetadata] = {}
        
        # Generate initial master key
        self.master_key_id = self._generate_key_id()
        self.master_key = self.generate_key()
        self._store_key(self.master_key_id, self.master_key, "ChaCha20-Poly1305")
    
    def generate_key(self) -> bytes:
        """Generate a new cryptographic key
        
        Returns:
            32-byte cryptographic key
        """
        return os.urandom(self.key_size)
    
    def _generate_key_id(self) -> str:
        """Generate a unique key identifier"""
        return secrets.token_hex(16)
    
    def _store_key(self, key_id: str, key: bytes, algorithm: str, 
                  expires_in_hours: Optional[int] = None, 
                  max_usage: Optional[int] = None):
        """Store a key with metadata"""
        expires_at = None
        if expires_in_hours:
            expires_at = datetime.utcnow() + timedelta(hours=expires_in_hours)
        
        self.active_keys[key_id] = key
        self.key_metadata[key_id] = KeyMetadata(
            key_id=key_id,
            algorithm=algorithm,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
            max_usage=max_usage
        )
    
    def encrypt_message(self, plaintext: Union[str, bytes], 
                       key_id: Optional[str] = None,
                       associated_data: Optional[bytes] = None) -> EncryptionResult:
        """Encrypt message using ChaCha20-Poly1305
        
        Args:
            plaintext: Data to encrypt
            key_id: Key ID to use (uses master key if None)
            associated_data: Additional authenticated data
            
        Returns:
            EncryptionResult with ciphertext and metadata
            
        Raises:
            CryptographicError: If encryption fails
        """
        try:
            # Use master key if no key specified
            if key_id is None:
                key_id = self.master_key_id
            
            # Get key
            key = self._get_active_key(key_id)
            
            # Convert plaintext to bytes if needed
            if isinstance(plaintext, str):
                plaintext_bytes = plaintext.encode('utf-8')
            else:
                plaintext_bytes = plaintext
            
            # Generate nonce
            nonce = os.urandom(self.nonce_size)
            
            # Create cipher
            cipher = ChaCha20Poly1305(key)
            
            # Encrypt
            ciphertext = cipher.encrypt(nonce, plaintext_bytes, associated_data)
            
            # Update key usage
            self._increment_key_usage(key_id)
            
            return EncryptionResult(
                ciphertext=ciphertext,
                nonce=nonce,
                algorithm="ChaCha20-Poly1305",
                key_id=key_id
            )
            
        except Exception as e:
            raise CryptographicError(f"Encryption failed: {str(e)}")
    
    def decrypt_message(self, encryption_result: EncryptionResult,
                       associated_data: Optional[bytes] = None) -> bytes:
        """Decrypt message
        
        Args:
            encryption_result: Result from encrypt_message
            associated_data: Additional authenticated data (must match encryption)
            
        Returns:
            Decrypted plaintext as bytes
            
        Raises:
            CryptographicError: If decryption fails
        """
        try:
            # Get key
            key = self._get_active_key(encryption_result.key_id)
            
            # Create cipher
            cipher = ChaCha20Poly1305(key)
            
            # Decrypt
            plaintext = cipher.decrypt(
                encryption_result.nonce,
                encryption_result.ciphertext,
                associated_data
            )
            
            return plaintext
            
        except Exception as e:
            raise CryptographicError(f"Decryption failed: {str(e)}")
    
    def _get_active_key(self, key_id: str) -> bytes:
        """Get an active key, checking expiration and usage limits"""
        if key_id not in self.active_keys:
            raise CryptographicError(f"Key {key_id} not found")
        
        metadata = self.key_metadata[key_id]
        
        # Check if key is active
        if not metadata.is_active:
            raise CryptographicError(f"Key {key_id} is not active")
        
        # Check expiration
        if metadata.expires_at and datetime.utcnow() > metadata.expires_at:
            metadata.is_active = False
            raise CryptographicError(f"Key {key_id} has expired")
        
        # Check usage limit
        if metadata.max_usage and metadata.usage_count >= metadata.max_usage:
            metadata.is_active = False
            raise CryptographicError(f"Key {key_id} usage limit exceeded")
        
        return self.active_keys[key_id]
    
    def _increment_key_usage(self, key_id: str):
        """Increment key usage counter"""
        if key_id in self.key_metadata:
            self.key_metadata[key_id].usage_count += 1
    
    def create_session_key(self, expires_in_hours: int = 24) -> str:
        """Create a new session key
        
        Args:
            expires_in_hours: Key expiration time in hours
            
        Returns:
            Key ID for the new session key
        """
        key_id = self._generate_key_id()
        key = self.generate_key()
        
        self._store_key(
            key_id, key, "ChaCha20-Poly1305", 
            expires_in_hours=expires_in_hours
        )
        
        return key_id
    
    def rotate_master_key(self) -> str:
        """Rotate the master key
        
        Returns:
            New master key ID
        """
        # Deactivate old master key
        if self.master_key_id in self.key_metadata:
            self.key_metadata[self.master_key_id].is_active = False
        
        # Generate new master key
        self.master_key_id = self._generate_key_id()
        self.master_key = self.generate_key()
        self._store_key(self.master_key_id, self.master_key, "ChaCha20-Poly1305")
        
        return self.master_key_id
    
    def revoke_key(self, key_id: str):
        """Revoke a key
        
        Args:
            key_id: Key ID to revoke
        """
        if key_id in self.key_metadata:
            self.key_metadata[key_id].is_active = False
    
    def get_key_info(self, key_id: str) -> Dict[str, Any]:
        """Get information about a key
        
        Args:
            key_id: Key ID
            
        Returns:
            Dictionary with key information
        """
        if key_id not in self.key_metadata:
            raise CryptographicError(f"Key {key_id} not found")
        
        metadata = self.key_metadata[key_id]
        
        return {
            "key_id": metadata.key_id,
            "algorithm": metadata.algorithm,
            "created_at": metadata.created_at,
            "expires_at": metadata.expires_at,
            "usage_count": metadata.usage_count,
            "max_usage": metadata.max_usage,
            "is_active": metadata.is_active,
            "is_expired": metadata.expires_at and datetime.utcnow() > metadata.expires_at
        }
    
    def list_keys(self) -> List[Dict[str, Any]]:
        """List all keys
        
        Returns:
            List of key information dictionaries
        """
        return [self.get_key_info(key_id) for key_id in self.key_metadata.keys()]
    
    def cleanup_expired_keys(self):
        """Remove expired and inactive keys"""
        current_time = datetime.utcnow()
        keys_to_remove = []
        
        for key_id, metadata in self.key_metadata.items():
            if (not metadata.is_active or 
                (metadata.expires_at and current_time > metadata.expires_at)):
                keys_to_remove.append(key_id)
        
        for key_id in keys_to_remove:
            if key_id != self.master_key_id:  # Never remove master key
                del self.active_keys[key_id]
                del self.key_metadata[key_id]
    
    def cleanup(self):
        """Cleanup crypto resources"""
        # Clear sensitive key material from memory
        for key_id in list(self.active_keys.keys()):
            if key_id != self.master_key_id:  # Keep master key
                del self.active_keys[key_id]
        
        # Clear expired keys
        self.cleanup_expired_keys()


class Argon2KeyDerivation:
    """Argon2 key derivation for password hashing and key stretching"""
    
    def __init__(self, 
                 time_cost: int = 3,
                 memory_cost: int = 65536,  # 64 MB
                 parallelism: int = 1,
                 hash_len: int = 32,
                 salt_len: int = 16):
        
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.hash_len = hash_len
        self.salt_len = salt_len
        
        # Create hasher instance
        self.hasher = argon2.PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            salt_len=salt_len
        )
    
    def derive_key(self, password: Union[str, bytes], 
                  salt: Optional[bytes] = None) -> Dict[str, Any]:
        """Derive key from password using Argon2id
        
        Args:
            password: Password to derive key from
            salt: Salt bytes (generated if None)
            
        Returns:
            Dictionary with derived key and parameters
        """
        if isinstance(password, str):
            password_bytes = password.encode('utf-8')
        else:
            password_bytes = password
        
        if salt is None:
            salt = os.urandom(self.salt_len)
        
        try:
            # Use Argon2id variant for balanced security
            derived_key = argon2.low_level.hash_secret_raw(
                secret=password_bytes,
                salt=salt,
                time_cost=self.time_cost,
                memory_cost=self.memory_cost,
                parallelism=self.parallelism,
                hash_len=self.hash_len,
                type=argon2.Type.ID
            )
            
            return {
                'key': derived_key,
                'salt': salt,
                'parameters': {
                    'time_cost': self.time_cost,
                    'memory_cost': self.memory_cost,
                    'parallelism': self.parallelism,
                    'hash_len': self.hash_len,
                    'type': 'Argon2id'
                }
            }
            
        except Exception as e:
            raise CryptographicError(f"Key derivation failed: {str(e)}")
    
    def hash_password(self, password: Union[str, bytes]) -> str:
        """Hash password for storage
        
        Args:
            password: Password to hash
            
        Returns:
            Argon2 hash string
        """
        if isinstance(password, bytes):
            password = password.decode('utf-8')
        
        try:
            return self.hasher.hash(password)
        except Exception as e:
            raise CryptographicError(f"Password hashing failed: {str(e)}")
    
    def verify_password(self, password: Union[str, bytes], 
                       hash_string: str) -> bool:
        """Verify password against hash
        
        Args:
            password: Password to verify
            hash_string: Stored hash string
            
        Returns:
            True if password matches, False otherwise
        """
        if isinstance(password, bytes):
            password = password.decode('utf-8')
        
        try:
            self.hasher.verify(hash_string, password)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False
        except Exception as e:
            raise CryptographicError(f"Password verification failed: {str(e)}")
    
    def check_needs_rehash(self, hash_string: str) -> bool:
        """Check if hash needs to be updated with new parameters
        
        Args:
            hash_string: Stored hash string
            
        Returns:
            True if rehash is needed, False otherwise
        """
        try:
            return self.hasher.check_needs_rehash(hash_string)
        except Exception:
            return True  # If we can't parse it, assume it needs rehash


class SecureRandom:
    """Cryptographically secure random number generation"""
    
    @staticmethod
    def generate_token(length: int = 32) -> str:
        """Generate a secure random token
        
        Args:
            length: Token length in bytes
            
        Returns:
            Hex-encoded token string
        """
        return secrets.token_hex(length)
    
    @staticmethod
    def generate_bytes(length: int) -> bytes:
        """Generate secure random bytes
        
        Args:
            length: Number of bytes to generate
            
        Returns:
            Random bytes
        """
        return secrets.token_bytes(length)
    
    @staticmethod
    def generate_urlsafe_token(length: int = 32) -> str:
        """Generate URL-safe random token
        
        Args:
            length: Token length in bytes
            
        Returns:
            URL-safe token string
        """
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_numeric_code(digits: int = 6) -> str:
        """Generate numeric code
        
        Args:
            digits: Number of digits
            
        Returns:
            Numeric code string
        """
        max_value = 10 ** digits
        code = secrets.randbelow(max_value)
        return f"{code:0{digits}d}"


class MessageAuthentication:
    """Message authentication using HMAC"""
    
    def __init__(self, key: bytes, algorithm: str = "sha256"):
        self.key = key
        self.algorithm = algorithm
        
        # Map algorithm names to hashlib functions
        self.hash_functions = {
            "sha256": hashes.SHA256,
            "sha384": hashes.SHA384,
            "sha512": hashes.SHA512
        }
        
        if algorithm not in self.hash_functions:
            raise CryptographicError(f"Unsupported hash algorithm: {algorithm}")
    
    def sign_message(self, message: Union[str, bytes]) -> bytes:
        """Create HMAC signature for message
        
        Args:
            message: Message to sign
            
        Returns:
            HMAC signature bytes
        """
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            message_bytes = message
        
        return hmac.new(
            self.key,
            message_bytes,
            getattr(hashlib, self.algorithm)
        ).digest()
    
    def verify_signature(self, message: Union[str, bytes], 
                        signature: bytes) -> bool:
        """Verify HMAC signature
        
        Args:
            message: Original message
            signature: HMAC signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            expected_signature = self.sign_message(message)
            return hmac.compare_digest(signature, expected_signature)
        except Exception:
            return False
    
    def sign_and_encode(self, message: Union[str, bytes]) -> str:
        """Sign message and return base64-encoded signature
        
        Args:
            message: Message to sign
            
        Returns:
            Base64-encoded signature
        """
        import base64
        signature = self.sign_message(message)
        return base64.b64encode(signature).decode('ascii')
    
    def verify_encoded_signature(self, message: Union[str, bytes], 
                               encoded_signature: str) -> bool:
        """Verify base64-encoded signature
        
        Args:
            message: Original message
            encoded_signature: Base64-encoded signature
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            import base64
            signature = base64.b64decode(encoded_signature)
            return self.verify_signature(message, signature)
        except Exception:
            return False