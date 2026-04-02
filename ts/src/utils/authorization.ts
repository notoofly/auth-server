import type { AuthUser, GuardOptions } from "../types/index.js";

export function hasRole(user: AuthUser, role: string): boolean {
	return user.roles.includes(role);
}

export function hasPermission(user: AuthUser, permission: string): boolean {
	return user.permissions.includes(permission);
}

export function hasAnyRole(user: AuthUser, roles: readonly string[]): boolean {
	return roles.some((role) => hasRole(user, role));
}

export function hasAllRoles(user: AuthUser, roles: readonly string[]): boolean {
	return roles.every((role) => hasRole(user, role));
}

export function hasAnyPermission(
	user: AuthUser,
	permissions: readonly string[],
): boolean {
	return permissions.some((permission) => hasPermission(user, permission));
}

export function hasAllPermissions(
	user: AuthUser,
	permissions: readonly string[],
): boolean {
	return permissions.every((permission) => hasPermission(user, permission));
}

export function checkGuard(user: AuthUser, options: GuardOptions): boolean {
	const { roles, permissions } = options;

	if (roles && roles.length > 0) {
		if (!hasAnyRole(user, roles)) {
			return false;
		}
	}

	if (permissions && permissions.length > 0) {
		if (!hasAnyPermission(user, permissions)) {
			return false;
		}
	}

	return true;
}
