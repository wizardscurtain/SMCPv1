"""Unit tests for authentication mechanisms.

Tests the JWTAuthenticator, MFAManager, and SessionManager components.
"""

import pytest
import time
import jwt
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

from smcp_security.authentication import (
    JWTAuthenticator, MFAManager, SessionManager, AuthenticationConfig
)
from smcp_security.exceptions import AuthenticationError


class TestAuthenticationConfig:
    """Test authentication configuration."""
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_default_config_creation(self):
        """Test creation of default authentication config."""
        config = AuthenticationConfig(jwt_secret_key="test-key")
        
        assert config.jwt_secret_key == "test-key"
        assert config.jwt_algorithm == "HS256"
        assert config.jwt_expiry_seconds == 3600
        assert config.require_mfa is True
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_custom_config_creation(self):
        """Test creation of custom authentication config."""
        config = AuthenticationConfig(
            jwt_secret_key="custom-key",
            jwt_algorithm="HS512",
            jwt_expiry_seconds=7200,
            require_mfa=False
        )
        
        assert config.jwt_secret_key == "custom-key"
        assert config.jwt_algorithm == "HS512"
        assert config.jwt_expiry_seconds == 7200
        assert config.require_mfa is False


class TestJWTAuthenticator:
    """Test JWT authentication functionality."""
    
    @pytest.fixture
    def auth_config(self):
        return AuthenticationConfig(
            jwt_secret_key="test-secret-key-for-testing",
            jwt_expiry_seconds=3600,
            require_mfa=False  # Disabled for testing
        )
    
    @pytest.fixture
    def authenticator(self, auth_config):
        return JWTAuthenticator(auth_config)
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_token_generation(self, authenticator):
        """Test JWT token generation."""
        token = authenticator.generate_token(
            user_id="test_user",
            roles=["user"],
            permissions=["read"],
            mfa_verified=True
        )
        
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Decode token to verify contents
        payload = jwt.decode(
            token, 
            authenticator.config.jwt_secret_key, 
            algorithms=[authenticator.config.jwt_algorithm]
        )
        
        assert payload["user_id"] == "test_user"
        assert payload["roles"] == ["user"]
        assert payload["permissions"] == ["read"]
        assert payload["mfa_verified"] is True
        assert "iat" in payload
        assert "exp" in payload
        assert "jti" in payload
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_token_validation_success(self, authenticator):
        """Test successful token validation."""
        # Generate token
        token = authenticator.generate_token(
            user_id="test_user",
            roles=["user"],
            permissions=["read"]
        )
        
        # Validate token
        payload = authenticator.validate_token(token)
        
        assert payload["user_id"] == "test_user"
        assert payload["roles"] == ["user"]
        assert payload["permissions"] == ["read"]
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_token_validation_invalid_token(self, authenticator):
        """Test validation of invalid token."""
        invalid_token = "invalid.jwt.token"
        
        with pytest.raises(AuthenticationError, match="Invalid token"):
            authenticator.validate_token(invalid_token)
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_token_validation_expired_token(self, authenticator):
        """Test validation of expired token."""
        # Create expired token
        expired_payload = {
            "user_id": "test_user",
            "exp": int(time.time()) - 3600,  # Expired 1 hour ago
            "iat": int(time.time()) - 7200,
            "jti": "test-token-id"
        }
        
        expired_token = jwt.encode(
            expired_payload,
            authenticator.config.jwt_secret_key,
            algorithm=authenticator.config.jwt_algorithm
        )
        
        with pytest.raises(AuthenticationError, match="Token has expired"):
            authenticator.validate_token(expired_token)
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_token_revocation(self, authenticator):
        """Test token revocation functionality."""
        # Generate token
        token = authenticator.generate_token(user_id="test_user")
        
        # Token should be valid initially
        payload = authenticator.validate_token(token)
        assert payload["user_id"] == "test_user"
        
        # Revoke token
        authenticator.revoke_token(token)
        
        # Token should now be invalid
        with pytest.raises(AuthenticationError, match="Token has been revoked"):
            authenticator.validate_token(token)
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_token_refresh(self, authenticator):
        """Test token refresh functionality."""
        # Generate original token
        original_token = authenticator.generate_token(
            user_id="test_user",
            roles=["user"],
            permissions=["read"]
        )
        
        # Refresh token
        new_token = authenticator.refresh_token(original_token)
        
        # New token should be different
        assert new_token != original_token
        
        # New token should be valid
        payload = authenticator.validate_token(new_token)
        assert payload["user_id"] == "test_user"
        
        # Original token should be revoked
        with pytest.raises(AuthenticationError):
            authenticator.validate_token(original_token)
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_failed_attempt_tracking(self, authenticator):
        """Test failed authentication attempt tracking."""
        user_id = "test_user"
        ip_address = "192.168.1.100"
        
        # Initially not locked out
        assert not authenticator.is_locked_out(user_id, ip_address)
        
        # Record multiple failed attempts
        for _ in range(5):
            authenticator.record_failed_attempt(user_id, ip_address)
        
        # Should now be locked out
        assert authenticator.is_locked_out(user_id, ip_address)
        
        # Clear attempts
        authenticator.clear_failed_attempts(user_id, ip_address)
        
        # Should no longer be locked out
        assert not authenticator.is_locked_out(user_id, ip_address)
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_mfa_requirement_enforcement(self):
        """Test MFA requirement enforcement."""
        # Create authenticator with MFA required
        config = AuthenticationConfig(
            jwt_secret_key="test-key",
            require_mfa=True
        )
        authenticator = JWTAuthenticator(config)
        
        # Generate token without MFA
        token = authenticator.generate_token(
            user_id="test_user",
            mfa_verified=False
        )
        
        # Validation should fail
        with pytest.raises(AuthenticationError, match="Multi-factor authentication required"):
            authenticator.validate_token(token)
        
        # Generate token with MFA
        mfa_token = authenticator.generate_token(
            user_id="test_user",
            mfa_verified=True
        )
        
        # Validation should succeed
        payload = authenticator.validate_token(mfa_token)
        assert payload["user_id"] == "test_user"


class TestMFAManager:
    """Test multi-factor authentication functionality."""
    
    @pytest.fixture
    def mfa_manager(self):
        config = AuthenticationConfig(jwt_secret_key="test-key")
        return MFAManager(config)
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_totp_setup(self, mfa_manager):
        """Test TOTP setup for user."""
        user_id = "test_user"
        
        setup_data = mfa_manager.setup_totp(user_id)
        
        assert "secret" in setup_data
        assert "qr_code" in setup_data
        assert "provisioning_uri" in setup_data
        
        # Secret should be base32 encoded
        assert len(setup_data["secret"]) == 32
        
        # QR code should be base64 encoded image
        assert setup_data["qr_code"].startswith("data:image/png;base64,")
    
    @pytest.mark.unit
    @pytest.mark.auth
    @patch('pyotp.TOTP')
    def test_totp_verification_success(self, mock_totp, mfa_manager):
        """Test successful TOTP verification."""
        user_id = "test_user"
        
        # Setup TOTP
        mfa_manager.setup_totp(user_id)
        
        # Mock TOTP verification
        mock_totp_instance = Mock()
        mock_totp_instance.verify.return_value = True
        mock_totp.return_value = mock_totp_instance
        
        # Verify code
        result = mfa_manager.verify_totp(user_id, "123456")
        
        assert result is True
        mock_totp_instance.verify.assert_called_once_with("123456", valid_window=1)
    
    @pytest.mark.unit
    @pytest.mark.auth
    @patch('pyotp.TOTP')
    def test_totp_verification_failure(self, mock_totp, mfa_manager):
        """Test failed TOTP verification."""
        user_id = "test_user"
        
        # Setup TOTP
        mfa_manager.setup_totp(user_id)
        
        # Mock TOTP verification failure
        mock_totp_instance = Mock()
        mock_totp_instance.verify.return_value = False
        mock_totp.return_value = mock_totp_instance
        
        # Verify code
        result = mfa_manager.verify_totp(user_id, "wrong_code")
        
        assert result is False
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_backup_code_generation(self, mfa_manager):
        """Test backup code generation."""
        user_id = "test_user"
        
        codes = mfa_manager.generate_backup_codes(user_id, count=5)
        
        assert len(codes) == 5
        
        # All codes should be 8 characters
        for code in codes:
            assert len(code) == 8
            assert code.isupper()
            assert code.isalnum()
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_backup_code_verification(self, mfa_manager):
        """Test backup code verification and single-use nature."""
        user_id = "test_user"
        
        # Generate backup codes
        codes = mfa_manager.generate_backup_codes(user_id, count=3)
        test_code = codes[0]
        
        # First use should succeed
        result = mfa_manager.verify_backup_code(user_id, test_code)
        assert result is True
        
        # Second use should fail (single use)
        result = mfa_manager.verify_backup_code(user_id, test_code)
        assert result is False
        
        # Other codes should still work
        result = mfa_manager.verify_backup_code(user_id, codes[1])
        assert result is True
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_sms_code_sending(self, mfa_manager):
        """Test SMS code sending (mocked)."""
        user_id = "test_user"
        phone_number = "+1234567890"
        
        # Send SMS code
        result = mfa_manager.send_sms_code(user_id, phone_number)
        
        assert result is True
        
        # Verify code is stored
        assert user_id in mfa_manager.pending_verifications
        verification = mfa_manager.pending_verifications[user_id]
        assert verification["method"] == "sms"
        assert verification["phone"] == phone_number
        assert len(verification["code"]) == 6
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_email_code_sending(self, mfa_manager):
        """Test email code sending (mocked)."""
        user_id = "test_user"
        email = "test@example.com"
        
        # Send email code
        result = mfa_manager.send_email_code(user_id, email)
        
        assert result is True
        
        # Verify code is stored
        assert user_id in mfa_manager.pending_verifications
        verification = mfa_manager.pending_verifications[user_id]
        assert verification["method"] == "email"
        assert verification["email"] == email
        assert len(verification["code"]) == 6
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_temporary_code_verification(self, mfa_manager):
        """Test temporary code verification for SMS/email."""
        user_id = "test_user"
        
        # Send SMS code
        mfa_manager.send_sms_code(user_id, "+1234567890")
        
        # Get the generated code
        verification = mfa_manager.pending_verifications[user_id]
        correct_code = verification["code"]
        
        # Verify correct code
        result = mfa_manager.verify_temporary_code(user_id, correct_code)
        assert result is True
        
        # Code should be removed after successful verification
        assert user_id not in mfa_manager.pending_verifications
        
        # Send another code for failure test
        mfa_manager.send_sms_code(user_id, "+1234567890")
        
        # Verify wrong code
        result = mfa_manager.verify_temporary_code(user_id, "wrong_code")
        assert result is False
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_temporary_code_expiration(self, mfa_manager):
        """Test temporary code expiration."""
        user_id = "test_user"
        
        # Send code
        mfa_manager.send_sms_code(user_id, "+1234567890")
        
        # Manually expire the code
        verification = mfa_manager.pending_verifications[user_id]
        correct_code = verification["code"]
        verification["expires_at"] = datetime.utcnow() - timedelta(minutes=1)
        
        # Verification should fail due to expiration
        result = mfa_manager.verify_temporary_code(user_id, correct_code)
        assert result is False
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_mfa_status_checking(self, mfa_manager):
        """Test MFA status checking."""
        user_id = "test_user"
        
        # Initially MFA should not be enabled
        assert not mfa_manager.is_mfa_enabled(user_id)
        
        # Setup and verify TOTP
        mfa_manager.setup_totp(user_id)
        
        # Still not enabled until verified
        assert not mfa_manager.is_mfa_enabled(user_id)
        
        # Simulate successful verification
        mfa_manager.user_secrets[user_id]["verified"] = True
        
        # Now should be enabled
        assert mfa_manager.is_mfa_enabled(user_id)
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_mfa_disable(self, mfa_manager):
        """Test MFA disabling."""
        user_id = "test_user"
        
        # Setup MFA
        mfa_manager.setup_totp(user_id)
        mfa_manager.user_secrets[user_id]["verified"] = True
        
        # Verify it's enabled
        assert mfa_manager.is_mfa_enabled(user_id)
        
        # Disable MFA
        mfa_manager.disable_mfa(user_id)
        
        # Should no longer be enabled
        assert not mfa_manager.is_mfa_enabled(user_id)


class TestSessionManager:
    """Test session management functionality."""
    
    @pytest.fixture
    def session_manager(self):
        config = AuthenticationConfig(jwt_secret_key="test-key")
        return SessionManager(config)
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_session_creation(self, session_manager):
        """Test session creation."""
        user_id = "test_user"
        ip_address = "192.168.1.100"
        user_agent = "Test-Agent/1.0"
        
        session_id = session_manager.create_session(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        assert isinstance(session_id, str)
        assert len(session_id) > 0
        
        # Session should be stored
        assert session_id in session_manager.active_sessions
        session = session_manager.active_sessions[session_id]
        assert session["user_id"] == user_id
        assert session["ip_address"] == ip_address
        assert session["user_agent"] == user_agent
        assert session["is_active"] is True
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_session_validation_success(self, session_manager):
        """Test successful session validation."""
        user_id = "test_user"
        ip_address = "192.168.1.100"
        
        # Create session
        session_id = session_manager.create_session(user_id, ip_address)
        
        # Validate session
        result = session_manager.validate_session(session_id, ip_address)
        assert result is True
        
        # Last activity should be updated
        session = session_manager.active_sessions[session_id]
        assert session["last_activity"] is not None
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_session_validation_nonexistent(self, session_manager):
        """Test validation of non-existent session."""
        result = session_manager.validate_session("nonexistent-session")
        assert result is False
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_session_timeout(self, session_manager):
        """Test session timeout functionality."""
        user_id = "test_user"
        
        # Create session
        session_id = session_manager.create_session(user_id)
        
        # Manually set last activity to past timeout
        session = session_manager.active_sessions[session_id]
        session["last_activity"] = datetime.utcnow() - timedelta(
            seconds=session_manager.config.session_timeout_seconds + 1
        )
        
        # Validation should fail and terminate session
        result = session_manager.validate_session(session_id)
        assert result is False
        
        # Session should be marked as inactive
        assert not session_manager.active_sessions[session_id]["is_active"]
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_session_termination(self, session_manager):
        """Test manual session termination."""
        user_id = "test_user"
        
        # Create session
        session_id = session_manager.create_session(user_id)
        
        # Verify session is active
        assert session_manager.validate_session(session_id)
        
        # Terminate session
        session_manager.terminate_session(session_id)
        
        # Session should no longer be valid
        assert not session_manager.validate_session(session_id)
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_terminate_all_user_sessions(self, session_manager):
        """Test terminating all sessions for a user."""
        user_id = "test_user"
        
        # Create multiple sessions for the user
        session_ids = []
        for i in range(3):
            session_id = session_manager.create_session(
                user_id, f"192.168.1.{100 + i}"
            )
            session_ids.append(session_id)
        
        # All sessions should be valid
        for session_id in session_ids:
            assert session_manager.validate_session(session_id)
        
        # Terminate all sessions for user
        session_manager.terminate_all_sessions(user_id)
        
        # All sessions should now be invalid
        for session_id in session_ids:
            assert not session_manager.validate_session(session_id)
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_get_active_sessions(self, session_manager):
        """Test getting active sessions for a user."""
        user_id = "test_user"
        
        # Create sessions
        session_ids = []
        for i in range(2):
            session_id = session_manager.create_session(
                user_id, f"192.168.1.{100 + i}", f"Agent-{i}"
            )
            session_ids.append(session_id)
        
        # Get active sessions
        active_sessions = session_manager.get_active_sessions(user_id)
        
        assert len(active_sessions) == 2
        
        for session_info in active_sessions:
            assert "session_id" in session_info
            assert "ip_address" in session_info
            assert "user_agent" in session_info
            assert "created_at" in session_info
            assert "last_activity" in session_info
            assert session_info["session_id"] in session_ids
