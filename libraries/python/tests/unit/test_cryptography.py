"""Unit tests for cryptographic operations.

Tests the SMCPCrypto, Argon2KeyDerivation, and related components.
"""

import pytest
import os
from unittest.mock import Mock, patch

from smcp_security.cryptography import (
    SMCPCrypto, Argon2KeyDerivation, CryptoConfig
)
from smcp_security.exceptions import CryptographicError


class TestCryptoConfig:
    """Test cryptographic configuration."""
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_default_config_creation(self):
        """Test creation of default crypto config."""
        config = CryptoConfig()
        
        assert config.algorithm == "ChaCha20-Poly1305"
        assert config.key_size == 32
        assert config.nonce_size == 12
        assert config.tag_size == 16
        assert config.key_rotation_interval == 86400  # 24 hours
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_custom_config_creation(self):
        """Test creation of custom crypto config."""
        config = CryptoConfig(
            algorithm="AES-256-GCM",
            key_size=32,
            nonce_size=16,
            tag_size=16,
            key_rotation_interval=43200  # 12 hours
        )
        
        assert config.algorithm == "AES-256-GCM"
        assert config.key_size == 32
        assert config.nonce_size == 16
        assert config.tag_size == 16
        assert config.key_rotation_interval == 43200


class TestSMCPCrypto:
    """Test SMCP cryptographic operations."""
    
    @pytest.fixture
    def crypto(self):
        return SMCPCrypto()
    
    @pytest.fixture
    def crypto_with_key(self):
        crypto = SMCPCrypto()
        crypto.set_master_key(b'test_master_key_32_bytes_long!')
        return crypto
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_crypto_initialization(self, crypto):
        """Test crypto system initialization."""
        assert crypto.config.algorithm == "ChaCha20-Poly1305"
        assert isinstance(crypto.active_keys, dict)
        assert crypto.master_key is None
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_master_key_setting(self, crypto):
        """Test setting master key."""
        master_key = b'test_master_key_32_bytes_long!'
        
        crypto.set_master_key(master_key)
        
        assert crypto.master_key == master_key
        assert len(crypto.active_keys) > 0  # Should generate initial key
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_key_generation(self, crypto):
        """Test cryptographic key generation."""
        key = crypto.generate_key()
        
        assert isinstance(key, bytes)
        assert len(key) == crypto.config.key_size
        
        # Generate another key - should be different
        key2 = crypto.generate_key()
        assert key != key2
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_nonce_generation(self, crypto):
        """Test nonce generation."""
        nonce = crypto.generate_nonce()
        
        assert isinstance(nonce, bytes)
        assert len(nonce) == crypto.config.nonce_size
        
        # Generate another nonce - should be different
        nonce2 = crypto.generate_nonce()
        assert nonce != nonce2
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_encryption_decryption(self, crypto_with_key):
        """Test basic encryption and decryption."""
        plaintext = b"This is a test message for encryption"
        
        # Encrypt
        encrypted_data = crypto_with_key.encrypt(plaintext)
        
        assert "ciphertext" in encrypted_data
        assert "nonce" in encrypted_data
        assert "key_id" in encrypted_data
        assert encrypted_data["ciphertext"] != plaintext
        
        # Decrypt
        decrypted = crypto_with_key.decrypt(encrypted_data)
        
        assert decrypted == plaintext
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_encryption_with_custom_key(self, crypto):
        """Test encryption with custom key."""
        key = crypto.generate_key()
        plaintext = b"Test message with custom key"
        
        encrypted_data = crypto.encrypt(plaintext, key=key)
        decrypted = crypto.decrypt(encrypted_data, key=key)
        
        assert decrypted == plaintext
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_encryption_without_key_fails(self, crypto):
        """Test that encryption without key fails."""
        plaintext = b"Test message"
        
        with pytest.raises(CryptographicError, match="No encryption key available"):
            crypto.encrypt(plaintext)
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_decryption_with_wrong_key_fails(self, crypto):
        """Test that decryption with wrong key fails."""
        key1 = crypto.generate_key()
        key2 = crypto.generate_key()
        plaintext = b"Test message"
        
        encrypted_data = crypto.encrypt(plaintext, key=key1)
        
        with pytest.raises(CryptographicError, match="Decryption failed"):
            crypto.decrypt(encrypted_data, key=key2)
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_key_rotation(self, crypto_with_key):
        """Test key rotation functionality."""
        # Get initial key count
        initial_key_count = len(crypto_with_key.active_keys)
        
        # Rotate keys
        new_key_id = crypto_with_key.rotate_keys()
        
        assert isinstance(new_key_id, str)
        assert len(crypto_with_key.active_keys) == initial_key_count + 1
        assert crypto_with_key.current_key_id == new_key_id
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_old_key_cleanup(self, crypto_with_key):
        """Test cleanup of old keys."""
        # Generate multiple keys
        key_ids = []
        for i in range(5):
            key_id = crypto_with_key.rotate_keys()
            key_ids.append(key_id)
        
        # Should have multiple keys
        assert len(crypto_with_key.active_keys) > 1
        
        # Clean up old keys (keep only 2 most recent)
        crypto_with_key.cleanup_old_keys(keep_count=2)
        
        assert len(crypto_with_key.active_keys) == 2
        
        # Most recent keys should be kept
        assert key_ids[-1] in crypto_with_key.active_keys
        assert key_ids[-2] in crypto_with_key.active_keys
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_encrypt_decrypt_with_rotated_keys(self, crypto_with_key):
        """Test encryption/decryption works with key rotation."""
        plaintext = b"Test message for key rotation"
        
        # Encrypt with initial key
        encrypted_data = crypto_with_key.encrypt(plaintext)
        initial_key_id = encrypted_data["key_id"]
        
        # Rotate keys
        crypto_with_key.rotate_keys()
        
        # Should still be able to decrypt with old key
        decrypted = crypto_with_key.decrypt(encrypted_data)
        assert decrypted == plaintext
        
        # New encryption should use new key
        new_encrypted_data = crypto_with_key.encrypt(plaintext)
        assert new_encrypted_data["key_id"] != initial_key_id
        
        # Both should decrypt correctly
        assert crypto_with_key.decrypt(new_encrypted_data) == plaintext
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_key_derivation_from_master(self, crypto_with_key):
        """Test key derivation from master key."""
        # Derive key with specific purpose
        derived_key = crypto_with_key.derive_key("test_purpose", b"salt123")
        
        assert isinstance(derived_key, bytes)
        assert len(derived_key) == crypto_with_key.config.key_size
        
        # Same inputs should produce same key
        derived_key2 = crypto_with_key.derive_key("test_purpose", b"salt123")
        assert derived_key == derived_key2
        
        # Different inputs should produce different keys
        derived_key3 = crypto_with_key.derive_key("other_purpose", b"salt123")
        assert derived_key != derived_key3
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_secure_random_generation(self, crypto):
        """Test secure random number generation."""
        # Generate random bytes
        random_bytes = crypto.generate_random_bytes(32)
        
        assert isinstance(random_bytes, bytes)
        assert len(random_bytes) == 32
        
        # Should be different each time
        random_bytes2 = crypto.generate_random_bytes(32)
        assert random_bytes != random_bytes2
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_hash_generation(self, crypto):
        """Test cryptographic hash generation."""
        data = b"Test data for hashing"
        
        hash_value = crypto.hash_data(data)
        
        assert isinstance(hash_value, bytes)
        assert len(hash_value) == 32  # SHA-256 output
        
        # Same data should produce same hash
        hash_value2 = crypto.hash_data(data)
        assert hash_value == hash_value2
        
        # Different data should produce different hash
        hash_value3 = crypto.hash_data(b"Different data")
        assert hash_value != hash_value3
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_hmac_generation(self, crypto):
        """Test HMAC generation and verification."""
        key = crypto.generate_key()
        data = b"Test data for HMAC"
        
        hmac_value = crypto.generate_hmac(key, data)
        
        assert isinstance(hmac_value, bytes)
        assert len(hmac_value) == 32  # HMAC-SHA256 output
        
        # Verify HMAC
        is_valid = crypto.verify_hmac(key, data, hmac_value)
        assert is_valid is True
        
        # Wrong data should fail verification
        is_valid = crypto.verify_hmac(key, b"Wrong data", hmac_value)
        assert is_valid is False
        
        # Wrong key should fail verification
        wrong_key = crypto.generate_key()
        is_valid = crypto.verify_hmac(wrong_key, data, hmac_value)
        assert is_valid is False
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_digital_signature(self, crypto):
        """Test digital signature generation and verification."""
        # Generate key pair
        private_key, public_key = crypto.generate_key_pair()
        
        data = b"Test data for signing"
        
        # Sign data
        signature = crypto.sign_data(private_key, data)
        
        assert isinstance(signature, bytes)
        assert len(signature) > 0
        
        # Verify signature
        is_valid = crypto.verify_signature(public_key, data, signature)
        assert is_valid is True
        
        # Wrong data should fail verification
        is_valid = crypto.verify_signature(public_key, b"Wrong data", signature)
        assert is_valid is False
        
        # Wrong public key should fail verification
        _, wrong_public_key = crypto.generate_key_pair()
        is_valid = crypto.verify_signature(wrong_public_key, data, signature)
        assert is_valid is False
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_key_exchange(self, crypto):
        """Test key exchange functionality."""
        # Generate key pairs for two parties
        alice_private, alice_public = crypto.generate_key_pair()
        bob_private, bob_public = crypto.generate_key_pair()
        
        # Perform key exchange
        alice_shared = crypto.key_exchange(alice_private, bob_public)
        bob_shared = crypto.key_exchange(bob_private, alice_public)
        
        # Shared secrets should be the same
        assert alice_shared == bob_shared
        assert isinstance(alice_shared, bytes)
        assert len(alice_shared) == 32
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_password_hashing(self, crypto):
        """Test password hashing functionality."""
        password = "test_password_123"
        
        # Hash password
        password_hash = crypto.hash_password(password)
        
        assert isinstance(password_hash, str)
        assert len(password_hash) > 0
        assert password not in password_hash  # Should not contain plaintext
        
        # Verify password
        is_valid = crypto.verify_password(password, password_hash)
        assert is_valid is True
        
        # Wrong password should fail
        is_valid = crypto.verify_password("wrong_password", password_hash)
        assert is_valid is False
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_secure_comparison(self, crypto):
        """Test timing-safe string comparison."""
        string1 = "test_string_123"
        string2 = "test_string_123"
        string3 = "different_string"
        
        # Same strings should compare equal
        assert crypto.secure_compare(string1, string2) is True
        
        # Different strings should not compare equal
        assert crypto.secure_compare(string1, string3) is False
        
        # Test with bytes
        bytes1 = b"test_bytes_123"
        bytes2 = b"test_bytes_123"
        bytes3 = b"different_bytes"
        
        assert crypto.secure_compare(bytes1, bytes2) is True
        assert crypto.secure_compare(bytes1, bytes3) is False


class TestArgon2KeyDerivation:
    """Test Argon2 key derivation functionality."""
    
    @pytest.fixture
    def key_derivation(self):
        return Argon2KeyDerivation()
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_key_derivation_initialization(self, key_derivation):
        """Test key derivation initialization."""
        assert key_derivation.time_cost >= 1
        assert key_derivation.memory_cost >= 1024
        assert key_derivation.parallelism >= 1
        assert key_derivation.hash_length >= 16
        assert key_derivation.salt_length >= 16
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_salt_generation(self, key_derivation):
        """Test salt generation."""
        salt = key_derivation.generate_salt()
        
        assert isinstance(salt, bytes)
        assert len(salt) == key_derivation.salt_length
        
        # Should generate different salts
        salt2 = key_derivation.generate_salt()
        assert salt != salt2
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_key_derivation_with_salt(self, key_derivation):
        """Test key derivation with provided salt."""
        password = "test_password_123"
        salt = key_derivation.generate_salt()
        
        derived_key = key_derivation.derive_key(password, salt)
        
        assert isinstance(derived_key, bytes)
        assert len(derived_key) == key_derivation.hash_length
        
        # Same inputs should produce same key
        derived_key2 = key_derivation.derive_key(password, salt)
        assert derived_key == derived_key2
        
        # Different salt should produce different key
        different_salt = key_derivation.generate_salt()
        derived_key3 = key_derivation.derive_key(password, different_salt)
        assert derived_key != derived_key3
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_key_derivation_without_salt(self, key_derivation):
        """Test key derivation without provided salt (auto-generated)."""
        password = "test_password_123"
        
        result = key_derivation.derive_key_with_salt(password)
        
        assert "key" in result
        assert "salt" in result
        assert isinstance(result["key"], bytes)
        assert isinstance(result["salt"], bytes)
        assert len(result["key"]) == key_derivation.hash_length
        assert len(result["salt"]) == key_derivation.salt_length
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_password_hashing(self, key_derivation):
        """Test password hashing with Argon2."""
        password = "test_password_123"
        
        password_hash = key_derivation.hash_password(password)
        
        assert isinstance(password_hash, str)
        assert password_hash.startswith("$argon2")
        assert password not in password_hash
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_password_verification(self, key_derivation):
        """Test password verification with Argon2."""
        password = "test_password_123"
        
        # Hash password
        password_hash = key_derivation.hash_password(password)
        
        # Verify correct password
        is_valid = key_derivation.verify_password(password, password_hash)
        assert is_valid is True
        
        # Verify wrong password
        is_valid = key_derivation.verify_password("wrong_password", password_hash)
        assert is_valid is False
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_custom_parameters(self):
        """Test key derivation with custom parameters."""
        custom_kdf = Argon2KeyDerivation(
            time_cost=2,
            memory_cost=2048,
            parallelism=2,
            hash_length=64,
            salt_length=32
        )
        
        password = "test_password"
        salt = custom_kdf.generate_salt()
        
        derived_key = custom_kdf.derive_key(password, salt)
        
        assert len(derived_key) == 64  # Custom hash length
        assert len(salt) == 32  # Custom salt length
    
    @pytest.mark.unit
    @pytest.mark.crypto
    @pytest.mark.performance
    def test_performance_tuning(self, key_derivation, benchmark):
        """Test key derivation performance."""
        password = "test_password_for_performance"
        salt = key_derivation.generate_salt()
        
        def derive_key():
            return key_derivation.derive_key(password, salt)
        
        # Benchmark key derivation
        result = benchmark(derive_key)
        
        assert isinstance(result, bytes)
        assert len(result) == key_derivation.hash_length
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_memory_usage_control(self, key_derivation):
        """Test that memory usage is controlled."""
        # Test with different memory costs
        low_memory_kdf = Argon2KeyDerivation(memory_cost=1024)  # 1MB
        high_memory_kdf = Argon2KeyDerivation(memory_cost=4096)  # 4MB
        
        password = "test_password"
        salt = low_memory_kdf.generate_salt()
        
        # Both should work but with different resource usage
        key1 = low_memory_kdf.derive_key(password, salt)
        key2 = high_memory_kdf.derive_key(password, salt)
        
        assert isinstance(key1, bytes)
        assert isinstance(key2, bytes)
        # Keys will be different due to different parameters
        assert key1 != key2
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_parallelism_control(self, key_derivation):
        """Test parallelism parameter control."""
        # Test with different parallelism levels
        single_thread_kdf = Argon2KeyDerivation(parallelism=1)
        multi_thread_kdf = Argon2KeyDerivation(parallelism=4)
        
        password = "test_password"
        salt = single_thread_kdf.generate_salt()
        
        # Both should work
        key1 = single_thread_kdf.derive_key(password, salt)
        key2 = multi_thread_kdf.derive_key(password, salt)
        
        assert isinstance(key1, bytes)
        assert isinstance(key2, bytes)
        # Keys will be different due to different parameters
        assert key1 != key2
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_error_handling(self, key_derivation):
        """Test error handling in key derivation."""
        # Test with invalid inputs
        with pytest.raises(ValueError):
            key_derivation.derive_key("", b"salt")  # Empty password
        
        with pytest.raises(ValueError):
            key_derivation.derive_key("password", b"")  # Empty salt
        
        with pytest.raises(TypeError):
            key_derivation.derive_key(None, b"salt")  # None password
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_encoding_handling(self, key_derivation):
        """Test handling of different string encodings."""
        # Test with Unicode password
        unicode_password = "test_password_éáíóú"
        salt = key_derivation.generate_salt()
        
        derived_key = key_derivation.derive_key(unicode_password, salt)
        
        assert isinstance(derived_key, bytes)
        assert len(derived_key) == key_derivation.hash_length
        
        # Same Unicode password should produce same key
        derived_key2 = key_derivation.derive_key(unicode_password, salt)
        assert derived_key == derived_key2
