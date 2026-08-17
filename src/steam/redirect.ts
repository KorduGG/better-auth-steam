type TrustedOriginCheck = (
	url: string,
	settings?: { allowRelativePaths: boolean }
) => boolean;

export function normalizeRedirectTarget(
	input: string | null | undefined,
	baseURL: string,
	fallback: string,
	isTrustedOrigin: TrustedOriginCheck
): string {
	const isAllowed = (target: string): boolean =>
		isTrustedOrigin(target, { allowRelativePaths: true });

	if (input && isAllowed(input)) {
		return input;
	}

	if (isAllowed(fallback)) {
		return fallback;
	}

	return `${baseURL}/error`;
}

export function addErrorToRedirect(target: string, code: string, baseURL: string): string {
	const url = new URL(target, baseURL);
	url.searchParams.set('error', code);

	if (target.startsWith('/')) {
		return `${url.pathname}${url.search}${url.hash}`;
	}

	return url.toString();
}
