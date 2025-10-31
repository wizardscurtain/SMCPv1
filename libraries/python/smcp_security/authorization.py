"""Authorization Layer Implementation

Provides Role-Based Access Control (RBAC) with fine-grained permissions
and dynamic authorization for SMCP.
"""

import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .exceptions import AuthorizationError


class PermissionEffect(Enum):
    """Permission effect types"""
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class Permission:
    """Represents a permission with optional conditions"""
    action: str  # e.g., "mcp:execute", "file:read"
    resource: str = "*"  # Resource pattern, e.g., "tools/*", "files:/home/*"
    effect: PermissionEffect = PermissionEffect.ALLOW
    conditions: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Role:
    """Represents a role with permissions and metadata"""
    name: str
    permissions: List[Permission] = field(default_factory=list)
    description: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    is_active: bool = True
    parent_roles: List[str] = field(default_factory=list)  # Role inheritance


@dataclass
class AuthorizationContext:
    """Context information for authorization decisions"""
    user_id: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    time_of_day: Optional[int] = None  # Hour of day (0-23)
    day_of_week: Optional[int] = None  # Day of week (0-6)
    resource_attributes: Dict[str, Any] = field(default_factory=dict)
    session_attributes: Dict[str, Any] = field(default_factory=dict)


class RBACManager:
    """Role-Based Access Control Manager"""
    
    def __init__(self):
        self.roles: Dict[str, Role] = {}
        self.user_roles: Dict[str, Set[str]] = {}
        self.permission_cache: Dict[str, Dict[str, bool]] = {}  # Simple cache
        self.cache_ttl = 300  # 5 minutes
        self.cache_timestamps: Dict[str, datetime] = {}
    
    def define_role(self, role_name: str, permissions: List[str] = None, 
                   description: str = "", parent_roles: List[str] = None) -> Role:
        """Define a new role with permissions
        
        Args:
            role_name: Name of the role
            permissions: List of permission strings
            description: Role description
            parent_roles: List of parent role names for inheritance
            
        Returns:
            Created Role object
        """
        # Convert permission strings to Permission objects
        perm_objects = []
        for perm_str in (permissions or []):
            perm_objects.append(self._parse_permission_string(perm_str))
        
        role = Role(
            name=role_name,
            permissions=perm_objects,
            description=description,
            parent_roles=parent_roles or []
        )
        
        self.roles[role_name] = role
        self._clear_cache()  # Clear cache when roles change
        
        return role
    
    def _parse_permission_string(self, perm_str: str) -> Permission:
        """Parse permission string into Permission object
        
        Format: [effect:]action[:resource]
        Examples:
            - "mcp:execute" -> allow mcp:execute on *
            - "deny:file:read:/etc/*" -> deny file:read on /etc/*
            - "mcp:*" -> allow all mcp actions
        """
        parts = perm_str.split(":")
        
        if len(parts) == 1:
            # Simple action
            return Permission(action=parts[0])
        elif len(parts) == 2:
            # action:resource or effect:action
            if parts[0] in ["allow", "deny"]:
                effect = PermissionEffect(parts[0])
                return Permission(action=parts[1], effect=effect)
            else:
                return Permission(action=parts[0], resource=parts[1])
        elif len(parts) == 3:
            # effect:action:resource
            if parts[0] in ["allow", "deny"]:
                effect = PermissionEffect(parts[0])
                return Permission(action=parts[1], resource=parts[2], effect=effect)
            else:
                # Treat as action:resource:extra_resource
                return Permission(action=parts[0], resource=":".join(parts[1:]))
        else:
            # More complex format with conditions (simplified)
            effect = PermissionEffect(parts[0]) if parts[0] in ["allow", "deny"] else PermissionEffect.ALLOW
            action = parts[1] if parts[0] in ["allow", "deny"] else parts[0]
            resource = parts[2] if parts[0] in ["allow", "deny"] else parts[1]
            
            return Permission(action=action, resource=resource, effect=effect)
    
    def assign_role(self, user_id: str, role_name: str):
        """Assign a role to a user
        
        Args:
            user_id: User ID
            role_name: Role name to assign
            
        Raises:
            AuthorizationError: If role doesn't exist
        """
        if role_name not in self.roles:
            raise AuthorizationError(f"Role '{role_name}' does not exist")
        
        if user_id not in self.user_roles:
            self.user_roles[user_id] = set()
        
        self.user_roles[user_id].add(role_name)
        self._clear_user_cache(user_id)
    
    def revoke_role(self, user_id: str, role_name: str):
        """Revoke a role from a user
        
        Args:
            user_id: User ID
            role_name: Role name to revoke
        """
        if user_id in self.user_roles:
            self.user_roles[user_id].discard(role_name)
            self._clear_user_cache(user_id)
    
    def check_permission(self, user_id: str, required_permission: str, 
                        resource: str = "*", 
                        context: AuthorizationContext = None) -> bool:
        """Check if user has required permission
        
        Args:
            user_id: User ID to check
            required_permission: Permission action to check
            resource: Resource being accessed
            context: Authorization context for dynamic decisions
            
        Returns:
            True if permission is granted, False otherwise
        """
        # Check cache first
        cache_key = f"{user_id}:{required_permission}:{resource}"
        if self._is_cached(cache_key):
            return self.permission_cache[user_id][cache_key]
        
        # Get all user permissions (including inherited)
        user_permissions = self._get_effective_permissions(user_id)
        
        # Evaluate permissions (deny takes precedence)
        has_allow = False
        has_deny = False
        
        for permission in user_permissions:
            if self._matches_permission(permission, required_permission, resource):
                # Check conditions if present
                if self._evaluate_conditions(permission, context):
                    if permission.effect == PermissionEffect.ALLOW:
                        has_allow = True
                    elif permission.effect == PermissionEffect.DENY:
                        has_deny = True
        
        # Deny takes precedence
        result = has_allow and not has_deny
        
        # Cache result
        self._cache_result(user_id, cache_key, result)
        
        return result
    
    def _get_effective_permissions(self, user_id: str) -> List[Permission]:
        """Get all effective permissions for user (including inherited)
        
        Args:
            user_id: User ID
            
        Returns:
            List of all effective permissions
        """
        user_roles = self.user_roles.get(user_id, set())
        all_permissions = []
        
        # Collect permissions from all roles (including inherited)
        processed_roles = set()
        roles_to_process = list(user_roles)
        
        while roles_to_process:
            role_name = roles_to_process.pop(0)
            
            if role_name in processed_roles or role_name not in self.roles:
                continue
            
            processed_roles.add(role_name)
            role = self.roles[role_name]
            
            if role.is_active:
                all_permissions.extend(role.permissions)
                
                # Add parent roles to processing queue
                roles_to_process.extend(role.parent_roles)
        
        return all_permissions
    
    def _matches_permission(self, permission: Permission, 
                          required_action: str, resource: str) -> bool:
        """Check if permission matches required action and resource
        
        Args:
            permission: Permission to check
            required_action: Required action
            resource: Resource being accessed
            
        Returns:
            True if permission matches
        """
        # Reconstruct the full permission string for comparison
        perm_full = f"{permission.action}:{permission.resource}"
        
        # Check if the permission matches the required action
        if not self._matches_pattern(perm_full, required_action):
            # Also try matching just the action part
            if not self._matches_pattern(permission.action, required_action):
                return False
        
        return True
    
    def _matches_pattern(self, pattern: str, value: str) -> bool:
        """Check if value matches pattern (supports wildcards)
        
        Args:
            pattern: Pattern with possible wildcards (*)
            value: Value to match
            
        Returns:
            True if value matches pattern
        """
        if pattern == "*":
            return True
        
        # Convert wildcard pattern to regex
        regex_pattern = pattern.replace("*", ".*")
        regex_pattern = f"^{regex_pattern}$"
        
        return bool(re.match(regex_pattern, value))
    
    def _evaluate_conditions(self, permission: Permission, 
                           context: AuthorizationContext = None) -> bool:
        """Evaluate permission conditions
        
        Args:
            permission: Permission with conditions
            context: Authorization context
            
        Returns:
            True if conditions are met
        """
        if not permission.conditions or not context:
            return True
        
        for condition_type, condition_value in permission.conditions.items():
            if condition_type == "time_range":
                if not self._check_time_range(condition_value, context):
                    return False
            elif condition_type == "ip_range":
                if not self._check_ip_range(condition_value, context):
                    return False
            elif condition_type == "day_of_week":
                if not self._check_day_of_week(condition_value, context):
                    return False
            # Add more condition types as needed
        
        return True
    
    def _check_time_range(self, time_range: Dict[str, int], 
                         context: AuthorizationContext) -> bool:
        """Check if current time is within allowed range"""
        if context.time_of_day is None:
            return True
        
        start_hour = time_range.get("start", 0)
        end_hour = time_range.get("end", 23)
        
        return start_hour <= context.time_of_day <= end_hour
    
    def _check_ip_range(self, ip_ranges: List[str], 
                       context: AuthorizationContext) -> bool:
        """Check if IP address is in allowed ranges"""
        if not context.ip_address:
            return True
        
        # Simplified IP range checking (in production, use ipaddress module)
        for ip_range in ip_ranges:
            if ip_range == "*" or context.ip_address.startswith(ip_range.replace("*", "")):
                return True
        
        return False
    
    def _check_day_of_week(self, allowed_days: List[int], 
                          context: AuthorizationContext) -> bool:
        """Check if current day is allowed"""
        if context.day_of_week is None:
            return True
        
        return context.day_of_week in allowed_days
    
    def get_user_permissions(self, user_id: str) -> List[str]:
        """Get all permissions for a user
        
        Args:
            user_id: User ID
            
        Returns:
            List of permission strings
        """
        permissions = self._get_effective_permissions(user_id)
        
        return [
            f"{perm.effect.value}:{perm.action}:{perm.resource}"
            for perm in permissions
        ]
    
    def get_user_roles(self, user_id: str) -> List[str]:
        """Get roles assigned to user
        
        Args:
            user_id: User ID
            
        Returns:
            List of role names
        """
        return list(self.user_roles.get(user_id, set()))
    
    def list_roles(self) -> List[Dict[str, Any]]:
        """List all defined roles
        
        Returns:
            List of role information
        """
        return [
            {
                "name": role.name,
                "description": role.description,
                "permissions": len(role.permissions),
                "is_active": role.is_active,
                "created_at": role.created_at,
                "parent_roles": role.parent_roles
            }
            for role in self.roles.values()
        ]
    
    def delete_role(self, role_name: str):
        """Delete a role
        
        Args:
            role_name: Role name to delete
            
        Raises:
            AuthorizationError: If role is still assigned to users
        """
        # Check if role is still assigned
        assigned_users = [
            user_id for user_id, roles in self.user_roles.items()
            if role_name in roles
        ]
        
        if assigned_users:
            raise AuthorizationError(
                f"Cannot delete role '{role_name}': still assigned to users {assigned_users}"
            )
        
        if role_name in self.roles:
            del self.roles[role_name]
            self._clear_cache()
    
    def _is_cached(self, cache_key: str) -> bool:
        """Check if result is cached and still valid"""
        user_id = cache_key.split(":")[0]
        
        if (user_id not in self.permission_cache or 
            cache_key not in self.permission_cache[user_id]):
            return False
        
        # Check TTL
        if user_id in self.cache_timestamps:
            cache_time = self.cache_timestamps[user_id]
            if datetime.utcnow() - cache_time > timedelta(seconds=self.cache_ttl):
                self._clear_user_cache(user_id)
                return False
        
        return True
    
    def _cache_result(self, user_id: str, cache_key: str, result: bool):
        """Cache authorization result"""
        if user_id not in self.permission_cache:
            self.permission_cache[user_id] = {}
        
        self.permission_cache[user_id][cache_key] = result
        self.cache_timestamps[user_id] = datetime.utcnow()
    
    def _clear_cache(self):
        """Clear all cached results"""
        self.permission_cache.clear()
        self.cache_timestamps.clear()
    
    def _clear_user_cache(self, user_id: str):
        """Clear cached results for specific user"""
        if user_id in self.permission_cache:
            del self.permission_cache[user_id]
        if user_id in self.cache_timestamps:
            del self.cache_timestamps[user_id]
    
    def add_permission_to_role(self, role_name: str, permission_str: str):
        """Add permission to existing role
        
        Args:
            role_name: Role name
            permission_str: Permission string to add
            
        Raises:
            AuthorizationError: If role doesn't exist
        """
        if role_name not in self.roles:
            raise AuthorizationError(f"Role '{role_name}' does not exist")
        
        permission = self._parse_permission_string(permission_str)
        self.roles[role_name].permissions.append(permission)
        self._clear_cache()
    
    def remove_permission_from_role(self, role_name: str, permission_str: str):
        """Remove permission from role
        
        Args:
            role_name: Role name
            permission_str: Permission string to remove
        """
        if role_name not in self.roles:
            return
        
        role = self.roles[role_name]
        permission_to_remove = self._parse_permission_string(permission_str)
        
        # Remove matching permissions
        role.permissions = [
            perm for perm in role.permissions
            if not (perm.action == permission_to_remove.action and
                   perm.resource == permission_to_remove.resource and
                   perm.effect == permission_to_remove.effect)
        ]
        
        self._clear_cache()
    
    def create_authorization_context(self, user_id: str, 
                                   ip_address: str = None,
                                   user_agent: str = None,
                                   **kwargs) -> AuthorizationContext:
        """Create authorization context with current information
        
        Args:
            user_id: User ID
            ip_address: Client IP address
            user_agent: Client user agent
            **kwargs: Additional context attributes
            
        Returns:
            AuthorizationContext object
        """
        now = datetime.utcnow()
        
        return AuthorizationContext(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            time_of_day=now.hour,
            day_of_week=now.weekday(),
            **kwargs
        )