import type { NextFunction, Request, Response } from "express";
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

export interface ExpressAuthOptions extends JwtVerificationConfig {
	readonly extractFrom?: "header" | "cookie" | "both";
	readonly cookieName?: string;
}

export interface AuthenticatedRequest extends Request {
	auth?: AuthContext;
}

export function createAuthMiddleware(options: ExpressAuthOptions) {
	const verifier = new JwtVerifier(options);
	const extractFrom = options.extractFrom ?? "header";
	const cookieName = options.cookieName ?? "access_token";

	return async (
		req: AuthenticatedRequest,
		res: Response,
		next: NextFunction,
	): Promise<void> => {
		try {
			let token: string | null = null;

			switch (extractFrom) {
				case "header":
					token = extractTokenFromHeader(req.headers.authorization);
					break;
				case "cookie":
					token = extractTokenFromCookie(req.headers.cookie, cookieName);
					break;
				case "both":
					token =
						extractTokenFromHeader(req.headers.authorization) ??
						extractTokenFromCookie(req.headers.cookie, cookieName);
					break;
			}

			if (!token) {
				res.status(401).json({
					success: false,
					error: {
						code: "AUTH.TOKEN.MISSING",
						message: "Authentication token is required",
					},
					meta: {
						requestId: res.locals.requestId ?? "unknown",
						timestamp: new Date().toISOString(),
					},
				});
				return;
			}

			const user = await verifier.verifyAccessToken(token);
			req.auth = { user, token };

			next();
		} catch (error) {
			res.status(401).json({
				success: false,
				error: {
					code: "AUTH.TOKEN.INVALID",
					message: error instanceof Error ? error.message : "Invalid token",
				},
				meta: {
					requestId: res.locals.requestId ?? "unknown",
					timestamp: new Date().toISOString(),
				},
			});
		}
	};
}

export function createRoleGuard(role: string) {
	return (
		req: AuthenticatedRequest,
		res: Response,
		next: NextFunction,
	): void => {
		if (!req.auth?.user) {
			res.status(401).json({
				success: false,
				error: {
					code: "AUTH.REQUIRED",
					message: "Authentication required",
				},
				meta: {
					requestId: res.locals.requestId ?? "unknown",
					timestamp: new Date().toISOString(),
				},
			});
			return;
		}

		if (!req.auth.user.roles.includes(role)) {
			res.status(403).json({
				success: false,
				error: {
					code: "AUTH.ROLE.REQUIRED",
					message: `Role '${role}' is required`,
				},
				meta: {
					requestId: res.locals.requestId ?? "unknown",
					timestamp: new Date().toISOString(),
				},
			});
			return;
		}

		next();
	};
}

export function createPermissionGuard(permission: string) {
	return (
		req: AuthenticatedRequest,
		res: Response,
		next: NextFunction,
	): void => {
		if (!req.auth?.user) {
			res.status(401).json({
				success: false,
				error: {
					code: "AUTH.REQUIRED",
					message: "Authentication required",
				},
				meta: {
					requestId: res.locals.requestId ?? "unknown",
					timestamp: new Date().toISOString(),
				},
			});
			return;
		}

		if (!req.auth.user.permissions.includes(permission)) {
			res.status(403).json({
				success: false,
				error: {
					code: "AUTH.PERMISSION.REQUIRED",
					message: `Permission '${permission}' is required`,
				},
				meta: {
					requestId: res.locals.requestId ?? "unknown",
					timestamp: new Date().toISOString(),
				},
			});
			return;
		}

		next();
	};
}

export function createGuard(options: GuardOptions) {
	return (
		req: AuthenticatedRequest,
		res: Response,
		next: NextFunction,
	): void => {
		if (!req.auth?.user) {
			res.status(401).json({
				success: false,
				error: {
					code: "AUTH.REQUIRED",
					message: "Authentication required",
				},
				meta: {
					requestId: res.locals.requestId ?? "unknown",
					timestamp: new Date().toISOString(),
				},
			});
			return;
		}

		if (!checkGuard(req.auth.user, options)) {
			res.status(403).json({
				success: false,
				error: {
					code: "AUTH.GUARD.FAILED",
					message: "Access denied by authorization guard",
				},
				meta: {
					requestId: res.locals.requestId ?? "unknown",
					timestamp: new Date().toISOString(),
				},
			});
			return;
		}

		next();
	};
}
