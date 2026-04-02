export function extractTokenFromHeader(
	authHeader: string | undefined | null,
): string | null {
	if (!authHeader) {
		return null;
	}

	const parts = authHeader.split(" ");
	if (parts.length !== 2 || parts[0] !== "Bearer") {
		return null;
	}

	return parts[1] ?? null;
}

export function extractTokenFromCookie(
	cookieHeader: string | undefined | null,
	cookieName = "access_token",
): string | null {
	if (!cookieHeader) {
		return null;
	}

	const cookies = cookieHeader.split(";").map((cookie) => cookie.trim());
	for (const cookie of cookies) {
		const [name, value] = cookie.split("=");
		if (name === cookieName && value) {
			return decodeURIComponent(value);
		}
	}

	return null;
}
