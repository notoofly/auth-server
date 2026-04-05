import { Elysia } from "elysia";
import { JwtVerifier } from "../../core/jwt-verifier.js";
import type {
	AuthContext,
	GuardOptions,
	JwtVerificationConfig,
} from "../../types/index.js";
import { checkGuard } from "../../utils/authorization.js";
import {
	extractTokenFromCookie,
	extractTokenFromHeader,
} from "../../utils/token-extraction.js";

export interface ElysiaAuthOptions extends JwtVerificationConfig {
	extractFrom?: "header" | "cookie" | "both";
	cookieName?: string;
}

export interface AuthContextElysia {
	user: AuthContext["user"];
	token: string;
}

export type AuthPluginContext = {
	getAuth: () => Promise<AuthContextElysia | null>;
};

export function createAuthPlugin(options: ElysiaAuthOptions) {
	const verifier = new JwtVerifier(options);
	const extractFrom = options.extractFrom ?? "header";
	const cookieName = options.cookieName ?? "access_token";

	return new Elysia({ name: "auth" }).derive(
		{ as: "global" },
		async ({ request }) => {
			const authHeader = request.headers.get("authorization");
			const cookieHeader = request.headers.get("cookie");

			const extractToken = (): string | null => {
				switch (extractFrom) {
					case "header":
						return extractTokenFromHeader(authHeader);

					case "cookie":
						return extractTokenFromCookie(cookieHeader, cookieName);

					case "both":
						return (
							extractTokenFromHeader(authHeader) ??
							extractTokenFromCookie(cookieHeader, cookieName)
						);

					default:
						return null;
				}
			};

			const token = extractToken();

			return {
				getAuth: async (): Promise<AuthContextElysia | null> => {
					if (!token) return null;

					try {
						const user = await verifier.verifyAccessToken(token);

						return {
							user,
							token,
						};
					} catch {
						return null;
					}
				},
			};
		},
	);
}

/* ---------------- ROLE GUARD ---------------- */

export function createRoleGuard(role: string) {
	return new Elysia({ name: `role-guard-${role}` }).onBeforeHandle(
		async (ctx) => {
			const { getAuth, set } = ctx as typeof ctx & AuthPluginContext;

			const auth = await getAuth();

			if (!auth) {
				set.status = 401;
				return {
					success: false,
					error: {
						code: "AUTH.REQUIRED",
						message: "Authentication required",
					},
					meta: {
						timestamp: new Date().toISOString(),
					},
				};
			}

			if (!auth.user.roles?.includes(role)) {
				set.status = 403;
				return {
					success: false,
					error: {
						code: "AUTH.ROLE.REQUIRED",
						message: `Role '${role}' is required`,
					},
					meta: {
						timestamp: new Date().toISOString(),
					},
				};
			}

			return;
		},
	);
}

/* ---------------- PERMISSION GUARD ---------------- */

export function createPermissionGuard(permission: string) {
	return new Elysia({ name: `permission-guard-${permission}` }).onBeforeHandle(
		async (ctx) => {
			const { getAuth, set } = ctx as typeof ctx & AuthPluginContext;

			const auth = await getAuth();

			if (!auth) {
				set.status = 401;
				return {
					success: false,
					error: {
						code: "AUTH.REQUIRED",
						message: "Authentication required",
					},
					meta: {
						timestamp: new Date().toISOString(),
					},
				};
			}

			if (!auth.user.permissions?.includes(permission)) {
				set.status = 403;
				return {
					success: false,
					error: {
						code: "AUTH.PERMISSION.REQUIRED",
						message: `Permission '${permission}' is required`,
					},
					meta: {
						timestamp: new Date().toISOString(),
					},
				};
			}

			return;
		},
	);
}

/* ---------------- CUSTOM GUARD ---------------- */

export function createGuard(options: GuardOptions) {
	return new Elysia({ name: "custom-guard" }).onBeforeHandle(async (ctx) => {
		const { getAuth, set } = ctx as typeof ctx & AuthPluginContext;

		const auth = await getAuth();

		if (!auth) {
			set.status = 401;
			return {
				success: false,
				error: {
					code: "AUTH.REQUIRED",
					message: "Authentication required",
				},
				meta: {
					timestamp: new Date().toISOString(),
				},
			};
		}

		if (!checkGuard(auth.user, options)) {
			set.status = 403;
			return {
				success: false,
				error: {
					code: "AUTH.GUARD.FAILED",
					message: "Access denied by authorization guard",
				},
				meta: {
					timestamp: new Date().toISOString(),
				},
			};
		}

		return;
	});
}
