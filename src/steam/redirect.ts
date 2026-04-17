export function normalizeRedirectTarget(
	input: string | null | undefined,
	baseURL: string,
	fallback: string
): string {
	if (!input) {
		return fallback;
	}

	try {
		const base = new URL(baseURL);
		const candidate = new URL(input, base);
		if (candidate.origin !== base.origin) {
			return fallback;
		}
		return `${candidate.pathname}${candidate.search}${candidate.hash}`;
	} catch {
		return fallback;
	}
}
