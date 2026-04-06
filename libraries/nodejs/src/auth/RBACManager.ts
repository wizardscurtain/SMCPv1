/**
 * RBAC Manager
 * Role-Based Access Control with wildcard permission support.
 */

export class RBACManager {
  /** role name → set of permission strings */
  private readonly roles: Map<string, Set<string>> = new Map();
  /** userId → set of role names */
  private readonly userRoles: Map<string, Set<string>> = new Map();

  defineRole(roleName: string, permissions: string[]): void {
    this.roles.set(roleName, new Set(permissions));
  }

  /** Alias used by existing stub code */
  addRole(roleName: string, permissions: string[]): void {
    this.defineRole(roleName, permissions);
  }

  assignRole(userId: string, roleName: string): void {
    // Noop if role not defined
    if (!this.roles.has(roleName)) return;

    if (!this.userRoles.has(userId)) {
      this.userRoles.set(userId, new Set());
    }
    this.userRoles.get(userId)!.add(roleName);
  }

  revokeRole(userId: string, roleName: string): void {
    this.userRoles.get(userId)?.delete(roleName);
  }

  checkPermission(userId: string, permission: string): boolean {
    const userRoleNames = this.userRoles.get(userId) ?? new Set<string>();

    for (const roleName of userRoleNames) {
      const rolePerms = this.roles.get(roleName);
      if (!rolePerms) continue;

      for (const perm of rolePerms) {
        if (this._matchesPermission(perm, permission)) {
          return true;
        }
      }
    }

    return false;
  }

  /** Alias used by existing stub code */
  hasPermission(userId: string, permission: string): boolean {
    return this.checkPermission(userId, permission);
  }

  getUserRoles(userId: string): string[] {
    return Array.from(this.userRoles.get(userId) ?? []);
  }

  getUserPermissions(userId: string): string[] {
    const result = new Set<string>();
    const userRoleNames = this.userRoles.get(userId) ?? new Set<string>();

    for (const roleName of userRoleNames) {
      const rolePerms = this.roles.get(roleName);
      if (rolePerms) {
        for (const perm of rolePerms) {
          result.add(perm);
        }
      }
    }

    return Array.from(result);
  }

  /**
   * Check if a stored permission string grants the required permission.
   * Supports wildcard: `mcp:*` matches any `mcp:X`; `*` matches anything.
   */
  private _matchesPermission(stored: string, required: string): boolean {
    if (stored === '*') return true;
    if (stored === required) return true;

    // Pattern: stored ends with :* — match any value after the prefix
    if (stored.endsWith(':*')) {
      const prefix = stored.slice(0, -1); // 'mcp:' from 'mcp:*'
      if (required.startsWith(prefix)) return true;
    }

    // Convert wildcard to regex
    const regexPattern = '^' + stored.replace(/\*/g, '.*') + '$';
    return new RegExp(regexPattern).test(required);
  }
}
