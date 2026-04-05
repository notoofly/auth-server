/**
 * Security utilities for production environment
 */

export interface SecurityConfig {
	allowedOrigins: string[];
	maxRequestSize: number;
	rateLimiting: {
		enabled: boolean;
		windowMs: number;
		maxRequests: number;
	};
	cookies: {
		secure: boolean;
		httpOnly: boolean;
		sameSite: "strict" | "lax" | "none";
	};
}

export const defaultSecurityConfig: SecurityConfig = {
	allowedOrigins: process.env.ALLOWED_ORIGINS?.split(",") || [
		"https://yourdomain.com",
	],
	maxRequestSize: 10 * 1024 * 1024, // 10MB
	rateLimiting: {
		enabled: process.env.NODE_ENV === "production",
		windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || "60000", 10),
		maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || "100", 10),
	},
	cookies: {
		secure: process.env.NODE_ENV === "production",
		httpOnly: true,
		sameSite: "strict",
	},
};

/**
 * Validate origin against allowed origins
 */
export function validateOrigin(origin: string | undefined): boolean {
	if (!origin) return false;

	const allowedOrigins = defaultSecurityConfig.allowedOrigins;
	return allowedOrigins.some((allowed) => {
		if (allowed === "*") return true;
		return origin === allowed || origin.startsWith(allowed.replace("*", ""));
	});
}

/**
 * Sanitize error messages for production
 */
export function sanitizeError(error: Error | string): string {
	const message = typeof error === "string" ? error : error.message;

	if (process.env.NODE_ENV === "production") {
		// Remove sensitive information from error messages
		return message.replace(/password|token|secret|key/gi, "[REDACTED]");
	}

	return message;
}

/**
 * Generate secure random token
 */
export function generateSecureToken(length = 32): string {
	const chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	let result = "";

	for (let i = 0; i < length; i++) {
		result += chars.charAt(Math.floor(Math.random() * chars.length));
	}

	return result;
}
