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
	readonly extractFrom?: "header" | "cookie" | "both";
	readonly cookieName?: string;
}

export interface AuthContextElysia {
	readonly user: AuthContext["user"];
	readonly token: string;
}

export function createAuthPlugin(options: ElysiaAuthOptions) {
	const verifier = new JwtVerifier(options);
	const extractFrom = options.extractFrom ?? "header";
	const cookieName = options.cookieName ?? "access_token";

	return new Elysia({
		name: "auth",
		seed: options,
	})
		.derive(({ request, set }) => {
			return {
				async getAuth(): Promise<AuthContextElysia | null> {
					try {
						let token: string | null = null;

						switch (extractFrom) {
							case "header":
								token = extractTokenFromHeader(
									request.headers.get("authorization"),
								);
								break;
							case "cookie":
								token = extractTokenFromCookie(
									request.headers.get("cookie"),
									cookieName,
								);
								break;
							case "both":
								token =
									extractTokenFromHeader(
										request.headers.get("authorization"),
									) ??
									extractTokenFromCookie(
										request.headers.get("cookie"),
										cookieName,
									);
								break;
						}

						if (!token) {
							if (set) {
								set.status = 401;
								throw new Error("Authentication token is required");
							}
							return null;
						}

						const user = await verifier.verifyAccessToken(token);
						return { user, token };
					} catch (error) {
						if (set) {
							set.status = 401;
							throw error;
						}
						return null;
					}
				},
			};
		})
		.beforeHandle(({ getAuth, set }) => {
			return async () => {
				const auth = await getAuth();
				if (!auth) {
					set.status = 401;
					return {
						success: false,
						error: {
							code: "AUTH.TOKEN.MISSING",
							message: "Authentication token is required",
						},
						meta: {
							timestamp: new Date().toISOString(),
						},
					};
				}
			};
		});
}

export function createRoleGuard(role: string) {
	return new Elysia({ name: `role-guard-${role}` }).onBeforeHandle(
		({ getAuth, set }: any) => {
			return async () => {
				try {
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

					if (!auth.user.roles.includes(role)) {
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
				} catch (error) {
					set.status = 401;
					return {
						success: false,
						error: {
							code: "AUTH.TOKEN.INVALID",
							message: error instanceof Error ? error.message : "Invalid token",
						},
						meta: {
							timestamp: new Date().toISOString(),
						},
					};
				}
			};
		},
	);
}

export function createPermissionGuard(permission: string) {
	return new Elysia({ name: `permission-guard-${permission}` }).beforeHandle(
		({ getAuth, set }) => {
			return async () => {
				try {
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

					if (!auth.user.permissions.includes(permission)) {
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
				} catch (error) {
					set.status = 401;
					return {
						success: false,
						error: {
							code: "AUTH.TOKEN.INVALID",
							message: error instanceof Error ? error.message : "Invalid token",
						},
						meta: {
							timestamp: new Date().toISOString(),
						},
					};
				}
			};
		},
	);
}

export function createGuard(options: GuardOptions) {
	return new Elysia({ name: "custom-guard" }).beforeHandle(
		({ getAuth, set }) => {
			return async () => {
				try {
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
				} catch (error) {
					set.status = 401;
					return {
						success: false,
						error: {
							code: "AUTH.TOKEN.INVALID",
							message: error instanceof Error ? error.message : "Invalid token",
						},
						meta: {
							timestamp: new Date().toISOString(),
						},
					};
				}
			};
		},
	);
}
