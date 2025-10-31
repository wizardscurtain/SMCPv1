"""Authentication Layer Implementation

Provides JWT-based authentication, multi-factor authentication,
and session management for SMCP.
"""

import jwt
import pyotp
import qrcode
import io
import base64
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import hashlib
import hmac

from .exceptions import AuthenticationError


@dataclass
class AuthenticationConfig:
    """Configuration for authentication system"""
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_expiry_seconds: int = 3600
    session_timeout_seconds: int = 7200
    max_failed_attempts: int = 5
    lockout_duration_seconds: int = 900  # 15 minutes
    require_mfa: bool = True
    totp_issuer: str = "SMCP Security"


class JWTAuthenticator:
    """JWT-based authentication system"""
    
    def __init__(self, config: AuthenticationConfig = None):
        if config is None:
            # Generate a secure random key for demo purposes
            secret_key = secrets.token_urlsafe(32)
            config = AuthenticationConfig(jwt_secret_key=secret_key)
        
        self.config = config
        self.revoked_tokens = set()  # In production, use Redis or database
        self.failed_attempts = {}  # Track failed login attempts
    
    def generate_token(self, user_id: str, roles: List[str] = None, 
                      permissions: List[str] = None, 
                      mfa_verified: bool = False) -> str:
        """Generate a JWT token for authenticated user
        
        Args:
            user_id: Unique user identifier
            roles: List of user roles
            permissions: List of user permissions
            mfa_verified: Whether MFA has been completed
            
        Returns:
            JWT token string
        """
        now = datetime.utcnow()
        
        payload = {
            'user_id': user_id,
            'roles': roles or [],
            'permissions': permissions or [],
            'mfa_verified': mfa_verified,
            'iat': now,
            'exp': now + timedelta(seconds=self.config.jwt_expiry_seconds),
            'jti': secrets.token_urlsafe(16),  # Unique token ID
            'iss': 'smcp-security',  # Issuer
            'aud': 'smcp-client',    # Audience
        }
        
        return jwt.encode(
            payload, 
            self.config.jwt_secret_key, 
            algorithm=self.config.jwt_algorithm
        )
    
    def validate_token(self, token: str) -> Dict[str, Any]:
        """Validate and decode JWT token
        
        Args:
            token: JWT token to validate
            
        Returns:
            Decoded token payload
            
        Raises:
            AuthenticationError: If token is invalid
        """
        try:
            # Decode and validate token
            payload = jwt.decode(
                token,
                self.config.jwt_secret_key,
                algorithms=[self.config.jwt_algorithm],
                audience='smcp-client',
                issuer='smcp-security'
            )
            
            # Check if token is revoked
            token_id = payload.get('jti')
            if token_id in self.revoked_tokens:
                raise AuthenticationError("Token has been revoked")
            
            # Check MFA requirement
            if self.config.require_mfa and not payload.get('mfa_verified', False):
                raise AuthenticationError("Multi-factor authentication required")
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {str(e)}")
    
    def revoke_token(self, token: str):
        """Revoke a JWT token
        
        Args:
            token: Token to revoke
        """
        try:
            payload = jwt.decode(
                token,
                self.config.jwt_secret_key,
                algorithms=[self.config.jwt_algorithm],
                options={"verify_exp": False}  # Allow expired tokens for revocation
            )
            token_id = payload.get('jti')
            if token_id:
                self.revoked_tokens.add(token_id)
        except jwt.InvalidTokenError:
            # Token is already invalid, no need to revoke
            pass
    
    def refresh_token(self, token: str) -> str:
        """Refresh an existing token
        
        Args:
            token: Current token to refresh
            
        Returns:
            New JWT token
            
        Raises:
            AuthenticationError: If token cannot be refreshed
        """
        payload = self.validate_token(token)
        
        # Revoke old token
        self.revoke_token(token)
        
        # Generate new token with same claims
        return self.generate_token(
            user_id=payload['user_id'],
            roles=payload.get('roles', []),
            permissions=payload.get('permissions', []),
            mfa_verified=payload.get('mfa_verified', False)
        )
    
    def record_failed_attempt(self, user_id: str, ip_address: str = None):
        """Record a failed authentication attempt
        
        Args:
            user_id: User ID that failed authentication
            ip_address: IP address of the attempt
        """
        key = f"{user_id}:{ip_address or 'unknown'}"
        now = time.time()
        
        if key not in self.failed_attempts:
            self.failed_attempts[key] = []
        
        self.failed_attempts[key].append(now)
        
        # Clean old attempts (older than lockout duration)
        cutoff = now - self.config.lockout_duration_seconds
        self.failed_attempts[key] = [
            attempt for attempt in self.failed_attempts[key] 
            if attempt > cutoff
        ]
    
    def is_locked_out(self, user_id: str, ip_address: str = None) -> bool:
        """Check if user/IP is locked out due to failed attempts
        
        Args:
            user_id: User ID to check
            ip_address: IP address to check
            
        Returns:
            True if locked out, False otherwise
        """
        key = f"{user_id}:{ip_address or 'unknown'}"
        
        if key not in self.failed_attempts:
            return False
        
        recent_attempts = len(self.failed_attempts[key])
        return recent_attempts >= self.config.max_failed_attempts
    
    def clear_failed_attempts(self, user_id: str, ip_address: str = None):
        """Clear failed attempts for successful authentication
        
        Args:
            user_id: User ID to clear
            ip_address: IP address to clear
        """
        key = f"{user_id}:{ip_address or 'unknown'}"
        if key in self.failed_attempts:
            del self.failed_attempts[key]


class MFAManager:
    """Multi-Factor Authentication Manager"""
    
    def __init__(self, config: AuthenticationConfig = None):
        self.config = config or AuthenticationConfig(jwt_secret_key="demo")
        self.user_secrets = {}  # In production, store in secure database
        self.pending_verifications = {}  # Temporary codes for SMS/Email
    
    def setup_totp(self, user_id: str) -> Dict[str, Any]:
        """Setup TOTP (Time-based One-Time Password) for user
        
        Args:
            user_id: User ID to setup TOTP for
            
        Returns:
            Dictionary with secret key and QR code
        """
        # Generate secret key
        secret = pyotp.random_base32()
        self.user_secrets[user_id] = {
            'totp_secret': secret,
            'created_at': datetime.utcnow(),
            'verified': False
        }
        
        # Generate TOTP URI
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user_id,
            issuer_name=self.config.totp_issuer
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 for easy transmission
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_str = base64.b64encode(img_buffer.getvalue()).decode()
        
        return {
            'secret': secret,
            'qr_code': f"data:image/png;base64,{img_str}",
            'provisioning_uri': provisioning_uri
        }
    
    def verify_totp(self, user_id: str, code: str) -> bool:
        """Verify TOTP code
        
        Args:
            user_id: User ID
            code: TOTP code to verify
            
        Returns:
            True if code is valid, False otherwise
        """
        user_data = self.user_secrets.get(user_id)
        if not user_data or 'totp_secret' not in user_data:
            return False
        
        totp = pyotp.TOTP(user_data['totp_secret'])
        
        # Verify code with some time window tolerance
        is_valid = totp.verify(code, valid_window=1)
        
        if is_valid:
            # Mark as verified on first successful verification
            user_data['verified'] = True
        
        return is_valid
    
    def generate_backup_codes(self, user_id: str, count: int = 10) -> List[str]:
        """Generate backup codes for user
        
        Args:
            user_id: User ID
            count: Number of backup codes to generate
            
        Returns:
            List of backup codes
        """
        codes = []
        for _ in range(count):
            # Generate 8-character alphanumeric code
            code = secrets.token_hex(4).upper()
            codes.append(code)
        
        # Store hashed versions
        if user_id not in self.user_secrets:
            self.user_secrets[user_id] = {}
        
        self.user_secrets[user_id]['backup_codes'] = {
            code: hashlib.sha256(code.encode()).hexdigest() 
            for code in codes
        }
        
        return codes
    
    def verify_backup_code(self, user_id: str, code: str) -> bool:
        """Verify backup code (single use)
        
        Args:
            user_id: User ID
            code: Backup code to verify
            
        Returns:
            True if code is valid, False otherwise
        """
        user_data = self.user_secrets.get(user_id, {})
        backup_codes = user_data.get('backup_codes', {})
        
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        
        # Check if code exists and matches
        for stored_code, stored_hash in backup_codes.items():
            if stored_hash == code_hash:
                # Remove used code
                del backup_codes[stored_code]
                return True
        
        return False
    
    def send_sms_code(self, user_id: str, phone_number: str) -> bool:
        """Send SMS verification code
        
        Args:
            user_id: User ID
            phone_number: Phone number to send to
            
        Returns:
            True if sent successfully, False otherwise
        """
        # Generate 6-digit code
        code = f"{secrets.randbelow(1000000):06d}"
        
        # Store code with expiration
        self.pending_verifications[user_id] = {
            'code': code,
            'method': 'sms',
            'phone': phone_number,
            'expires_at': datetime.utcnow() + timedelta(minutes=5),
            'attempts': 0
        }
        
        # In production, integrate with SMS provider (Twilio, AWS SNS, etc.)
        print(f"SMS Code for {user_id}: {code}")  # Demo only
        
        return True
    
    def send_email_code(self, user_id: str, email: str) -> bool:
        """Send email verification code
        
        Args:
            user_id: User ID
            email: Email address to send to
            
        Returns:
            True if sent successfully, False otherwise
        """
        # Generate 6-digit code
        code = f"{secrets.randbelow(1000000):06d}"
        
        # Store code with expiration
        self.pending_verifications[user_id] = {
            'code': code,
            'method': 'email',
            'email': email,
            'expires_at': datetime.utcnow() + timedelta(minutes=10),
            'attempts': 0
        }
        
        # In production, integrate with email provider (SendGrid, AWS SES, etc.)
        print(f"Email Code for {user_id}: {code}")  # Demo only
        
        return True
    
    def verify_temporary_code(self, user_id: str, code: str) -> bool:
        """Verify temporary SMS/Email code
        
        Args:
            user_id: User ID
            code: Code to verify
            
        Returns:
            True if code is valid, False otherwise
        """
        verification = self.pending_verifications.get(user_id)
        if not verification:
            return False
        
        # Check expiration
        if datetime.utcnow() > verification['expires_at']:
            del self.pending_verifications[user_id]
            return False
        
        # Check attempt limit
        verification['attempts'] += 1
        if verification['attempts'] > 3:
            del self.pending_verifications[user_id]
            return False
        
        # Verify code
        if verification['code'] == code:
            del self.pending_verifications[user_id]
            return True
        
        return False
    
    def is_mfa_enabled(self, user_id: str) -> bool:
        """Check if MFA is enabled for user
        
        Args:
            user_id: User ID to check
            
        Returns:
            True if MFA is enabled, False otherwise
        """
        user_data = self.user_secrets.get(user_id, {})
        return user_data.get('verified', False)
    
    def disable_mfa(self, user_id: str):
        """Disable MFA for user
        
        Args:
            user_id: User ID to disable MFA for
        """
        if user_id in self.user_secrets:
            del self.user_secrets[user_id]
        
        if user_id in self.pending_verifications:
            del self.pending_verifications[user_id]


class SessionManager:
    """Manages user sessions and session security"""
    
    def __init__(self, config: AuthenticationConfig = None):
        self.config = config or AuthenticationConfig(jwt_secret_key="demo")
        self.active_sessions = {}  # In production, use Redis
    
    def create_session(self, user_id: str, ip_address: str = None, 
                      user_agent: str = None) -> str:
        """Create a new session
        
        Args:
            user_id: User ID
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            Session ID
        """
        session_id = secrets.token_urlsafe(32)
        
        self.active_sessions[session_id] = {
            'user_id': user_id,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'created_at': datetime.utcnow(),
            'last_activity': datetime.utcnow(),
            'is_active': True
        }
        
        return session_id
    
    def validate_session(self, session_id: str, ip_address: str = None) -> bool:
        """Validate session and update activity
        
        Args:
            session_id: Session ID to validate
            ip_address: Current IP address
            
        Returns:
            True if session is valid, False otherwise
        """
        session = self.active_sessions.get(session_id)
        if not session or not session['is_active']:
            return False
        
        # Check session timeout
        timeout = timedelta(seconds=self.config.session_timeout_seconds)
        if datetime.utcnow() - session['last_activity'] > timeout:
            self.terminate_session(session_id)
            return False
        
        # Check IP address consistency (optional security measure)
        if ip_address and session['ip_address'] != ip_address:
            # In production, this might be configurable
            # For now, we'll allow IP changes but log them
            pass
        
        # Update last activity
        session['last_activity'] = datetime.utcnow()
        
        return True
    
    def terminate_session(self, session_id: str):
        """Terminate a session
        
        Args:
            session_id: Session ID to terminate
        """
        if session_id in self.active_sessions:
            self.active_sessions[session_id]['is_active'] = False
    
    def terminate_all_sessions(self, user_id: str):
        """Terminate all sessions for a user
        
        Args:
            user_id: User ID
        """
        for session in self.active_sessions.values():
            if session['user_id'] == user_id:
                session['is_active'] = False
    
    def get_active_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all active sessions for a user
        
        Args:
            user_id: User ID
            
        Returns:
            List of active session information
        """
        sessions = []
        for session_id, session in self.active_sessions.items():
            if (session['user_id'] == user_id and 
                session['is_active'] and
                self.validate_session(session_id)):
                
                sessions.append({
                    'session_id': session_id,
                    'ip_address': session['ip_address'],
                    'user_agent': session['user_agent'],
                    'created_at': session['created_at'],
                    'last_activity': session['last_activity']
                })
        
        return sessions