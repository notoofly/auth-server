import type { JWTPayload } from "jose";

export interface AuthUser extends JWTPayload {
	readonly sub: string;
	readonly email?: string;
	readonly roles: readonly string[];
	readonly permissions: readonly string[];
	readonly iat: number;
	readonly exp: number;
	readonly iss: string;
	readonly aud: string;
}
