import { type CryptoKey, importJWK, type JWTPayload, jwtVerify } from "jose";
import type {
	AuthUser,
	JwksCache,
	JwtVerificationConfig,
} from "../types/index.js";

interface JwksResponse {
	keys: Array<{
		kty: string;
		kid: string;
		use?: string;
		alg?: string;
		n?: string;
		e?: string;
		x?: string;
		y?: string;
		crv?: string;
	}>;
}

export class JwtVerifier {
	private readonly config: JwtVerificationConfig;
	private cache: JwksCache | null = null;
	private fetchPromise: Promise<JwksCache> | null = null;

	constructor(config: JwtVerificationConfig) {
		this.config = {
			cacheTtl: 300000, // 5 minutes default
			...config,
		};
	}

	async verifyAccessToken(token: string): Promise<AuthUser> {
		try {
			// Decode token to get key ID
			const header = this.decodeTokenHeader(token);
			const keyId = header.kid;

			if (!keyId) {
				throw new Error("Token missing key ID (kid)");
			}

			// Get public key
			const publicKey = await this.getPublicKey(keyId!);

			// Verify token
			const { payload } = await jwtVerify(token, publicKey, {
				issuer: this.config.issuer,
				audience: this.config.audience,
				algorithms: ["RS256", "ES256"],
			});

			return this.mapPayloadToAuthUser(payload);
		} catch (error) {
			if (error instanceof Error) {
				throw new Error(`JWT verification failed: ${error.message}`);
			}
			throw new Error("JWT verification failed: Unknown error");
		}
	}

	async getUserFromToken(token: string): Promise<AuthUser> {
		return this.verifyAccessToken(token);
	}

	private async getPublicKey(keyId: string): Promise<CryptoKey | Uint8Array> {
		const jwks = await this.getJwks();
		const key = jwks.keys.find((k) => k.kid === keyId);

		if (!key) {
			throw new Error(`Key with ID ${keyId} not found in JWKS`);
		}

		return importJWK(key);
	}

	private async getJwks(): Promise<JwksCache> {
		// Check cache first
		if (this.cache && !this.isCacheExpired(this.cache)) {
			return this.cache;
		}

		// If fetch is in progress, wait for it
		if (this.fetchPromise) {
			return this.fetchPromise;
		}

		// Start new fetch
		this.fetchPromise = this.fetchJwks();
		return this.fetchPromise;
	}

	private async fetchJwks(): Promise<JwksCache> {
		try {
			const response = await fetch(this.config.jwksUri);
			if (!response.ok) {
				throw new Error(`HTTP ${response.status}: ${response.statusText}`);
			}

			const jwks = (await response.json()) as JwksResponse;
			const now = Date.now();

			this.cache = {
				keys: jwks.keys,
				fetchedAt: now,
				expiresAt: now + (this.config.cacheTtl ?? 300000),
			};

			return this.cache;
		} catch (error) {
			this.fetchPromise = null;
			throw error;
		} finally {
			this.fetchPromise = null;
		}
	}

	private isCacheExpired(cache: JwksCache): boolean {
		return Date.now() >= cache.expiresAt;
	}

	private decodeTokenHeader(token: string): { kid?: string; alg?: string } {
		const parts = token.split(".");
		if (parts.length !== 3) {
			throw new Error("Invalid token format");
		}

		try {
			const header = JSON.parse(atob(parts[0] ?? "{}"));
			return header;
		} catch {
			throw new Error("Failed to decode token header");
		}
	}

	private mapPayloadToAuthUser(payload: JWTPayload): AuthUser {
		return {
			sub: payload.sub!,
			email: typeof payload.email === "string" ? payload.email : "",
			roles: (payload.roles as string[]) ?? [],
			permissions: (payload.permissions as string[]) ?? [],
			iat: payload.iat!,
			exp: payload.exp!,
			iss: payload.iss!,
			aud:
				typeof payload.aud === "string"
					? payload.aud
					: Array.isArray(payload.aud)
						? (payload.aud[0] ?? "")
						: "",
		};
	}
}
