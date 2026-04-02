export interface AuthUser {
	readonly sub: string;
	readonly email?: string;
	readonly roles: readonly string[];
	readonly permissions: readonly string[];
	readonly iat: number;
	readonly exp: number;
	readonly iss: string;
	readonly aud: string;
}

export interface JwtVerificationConfig {
	readonly jwksUri: string;
	readonly issuer: string;
	readonly audience: string;
	readonly cacheTtl?: number;
}

export interface JwksCache {
	readonly keys: readonly any[];
	readonly fetchedAt: number;
	readonly expiresAt: number;
}

export type Algorithm = "RS256" | "ES256";

export interface GuardOptions {
	readonly roles?: readonly string[];
	readonly permissions?: readonly string[];
}

export interface AuthContext {
	readonly user: AuthUser;
	readonly token: string;
}

export class JwtVerificationError extends Error {
	constructor(
		message: string,
		public readonly code: string,
		public readonly token?: string,
	) {
		super(message);
		this.name = "JwtVerificationError";
	}
}

export class JwksFetchError extends Error {
	constructor(
		message: string,
		public readonly cause?: Error,
	) {
		super(message);
		this.name = "JwksFetchError";
	}
}
