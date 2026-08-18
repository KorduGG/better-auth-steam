const STEAM_OPENID_URL = 'https://steamcommunity.com/openid/login';
const OPENID_NAMESPACE = 'http://specs.openid.net/auth/2.0';
const STEAM_ID_REGEX = /^https:\/\/steamcommunity\.com\/openid\/id\/(\d+)$/;
const REQUIRED_SIGNED_FIELDS = [
	'op_endpoint',
	'claimed_id',
	'identity',
	'return_to',
	'response_nonce',
	'assoc_handle'
];
const STEAM_REQUEST_TIMEOUT_MS = 10_000;
const RESPONSE_NONCE_MAX_LENGTH = 255;
const RESPONSE_NONCE_MAX_AGE_MS = 10 * 60 * 1000;

function parseResponseNonce(value: string): number | undefined {
	if (value.length > RESPONSE_NONCE_MAX_LENGTH) {
		return undefined;
	}

	const match = value.match(
		/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z[\x21-\x7e]*$/
	);
	if (!match) {
		return undefined;
	}

	const [, year, month, day, hour, minute, second] = match;
	const timestamp = Date.UTC(
		Number(year),
		Number(month) - 1,
		Number(day),
		Number(hour),
		Number(minute),
		Number(second)
	);
	const date = new Date(timestamp);
	if (
		date.getUTCFullYear() !== Number(year) ||
		date.getUTCMonth() !== Number(month) - 1 ||
		date.getUTCDate() !== Number(day) ||
		date.getUTCHours() !== Number(hour) ||
		date.getUTCMinutes() !== Number(minute) ||
		date.getUTCSeconds() !== Number(second)
	) {
		return undefined;
	}

	return timestamp;
}

function parseDirectVerificationResponse(text: string): Map<string, string> {
	const fields = new Map<string, string>();
	for (const line of text.split(/\r?\n/)) {
		if (!line) {
			continue;
		}
		const separator = line.indexOf(':');
		if (separator < 1) {
			throw new Error('Invalid Steam OpenID verification response');
		}
		const key = line.slice(0, separator);
		if (fields.has(key)) {
			throw new Error(`Duplicate Steam OpenID verification field: ${key}`);
		}
		fields.set(key, line.slice(separator + 1));
	}
	return fields;
}

export function buildSteamOpenIDRedirectURL(realm: string, returnTo: string): string {
	const params = new URLSearchParams({
		'openid.ns': 'http://specs.openid.net/auth/2.0',
		'openid.mode': 'checkid_setup',
		'openid.return_to': returnTo,
		'openid.realm': realm,
		'openid.identity': 'http://specs.openid.net/auth/2.0/identifier_select',
		'openid.claimed_id': 'http://specs.openid.net/auth/2.0/identifier_select'
	});
	return `${STEAM_OPENID_URL}?${params.toString()}`;
}

export async function verifySteamOpenIDResponse(
	params: URLSearchParams,
	expectedReturnTo: string
): Promise<{
	responseNonce: string;
	responseNonceExpiresAt: Date;
	steamId: string;
}> {
	const fieldNames = new Set<string>();
	for (const [name] of params) {
		if (name.startsWith('openid.') && fieldNames.has(name)) {
			throw new Error(`Duplicate OpenID field: ${name}`);
		}
		fieldNames.add(name);
	}

	if (params.get('openid.ns') !== OPENID_NAMESPACE) {
		throw new Error('Invalid openid.ns');
	}
	if (params.get('openid.mode') !== 'id_res') {
		throw new Error('Invalid openid.mode');
	}
	if (params.get('openid.op_endpoint') !== STEAM_OPENID_URL) {
		throw new Error('Invalid openid.op_endpoint');
	}
	if (params.get('openid.return_to') !== expectedReturnTo) {
		throw new Error('Invalid openid.return_to');
	}

	const claimedId = params.get('openid.claimed_id');
	if (!claimedId) {
		throw new Error('Missing openid.claimed_id');
	}

	const match = claimedId.match(STEAM_ID_REGEX);
	if (!match) {
		throw new Error('Invalid openid.claimed_id format');
	}
	if (params.get('openid.identity') !== claimedId) {
		throw new Error('Invalid openid.identity');
	}

	for (const name of ['openid.assoc_handle', 'openid.signed', 'openid.sig']) {
		if (!params.get(name)) {
			throw new Error(`Missing ${name}`);
		}
	}
	const associationHandle = params.get('openid.assoc_handle')!;
	if (associationHandle.length > 255 || !/^[\x21-\x7e]+$/.test(associationHandle)) {
		throw new Error('Invalid openid.assoc_handle');
	}
	const signature = params.get('openid.sig')!;
	if (
		!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
			signature
		)
	) {
		throw new Error('Invalid openid.sig');
	}

	const responseNonce = params.get('openid.response_nonce');
	if (!responseNonce) {
		throw new Error('Missing openid.response_nonce');
	}
	const nonceTimestamp = parseResponseNonce(responseNonce);
	if (
		nonceTimestamp === undefined ||
		Math.abs(Date.now() - nonceTimestamp) > RESPONSE_NONCE_MAX_AGE_MS
	) {
		throw new Error('Invalid openid.response_nonce');
	}

	const signedFieldList = params.get('openid.signed')!.split(',');
	const signedFields = new Set(signedFieldList);
	if (
		signedFields.size !== signedFieldList.length ||
		signedFieldList.some((field) => !/^[A-Za-z0-9_.-]+$/.test(field))
	) {
		throw new Error('Invalid openid.signed');
	}
	for (const field of REQUIRED_SIGNED_FIELDS) {
		if (!signedFields.has(field)) {
			throw new Error(`Missing signed OpenID field: ${field}`);
		}
	}

	const verifyParams = new URLSearchParams();
	for (const [key, value] of params.entries()) {
		if (key.startsWith('openid.')) {
			verifyParams.set(key, value);
		}
	}
	verifyParams.set('openid.mode', 'check_authentication');

	const response = await fetch(STEAM_OPENID_URL, {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: verifyParams.toString(),
		redirect: 'manual',
		signal: AbortSignal.timeout(STEAM_REQUEST_TIMEOUT_MS)
	});
	if (response.status !== 200) {
		throw new Error(`Steam OpenID error: ${response.status}`);
	}

	const fields = parseDirectVerificationResponse(await response.text());
	if (
		fields.get('ns') !== OPENID_NAMESPACE ||
		fields.get('is_valid') !== 'true'
	) {
		throw new Error('Steam OpenID verification failed');
	}

	return {
		responseNonce,
		responseNonceExpiresAt: new Date(
			nonceTimestamp + RESPONSE_NONCE_MAX_AGE_MS
		),
		steamId: match[1]
	};
}

export interface SteamPlayerSummary {
	steamid: string;
	personaname: string;
	avatarfull: string;
	profileurl: string;
	[key: string]: unknown;
}

export async function fetchSteamPlayerSummary(
	steamId: string,
	apiKey: string
): Promise<SteamPlayerSummary> {
	const url = `https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=${encodeURIComponent(apiKey)}&steamids=${encodeURIComponent(steamId)}`;
	const response = await fetch(url, {
		redirect: 'manual',
		signal: AbortSignal.timeout(STEAM_REQUEST_TIMEOUT_MS)
	});
	if (!response.ok) {
		throw new Error(`Steam API error: ${response.status}`);
	}
	const data = (await response.json()) as { response?: { players?: unknown[] } };
	const player = data?.response?.players?.[0];
	if (!player || typeof player !== 'object') {
		throw new Error('Player not found in Steam API response');
	}
	const candidate = player as Partial<SteamPlayerSummary>;
	if (candidate.steamid !== steamId) {
		throw new Error('Steam profile identity mismatch');
	}
	if (
		typeof candidate.personaname !== 'string' ||
		!candidate.personaname ||
		typeof candidate.avatarfull !== 'string' ||
		typeof candidate.profileurl !== 'string'
	) {
		throw new Error('Invalid Steam profile response');
	}
	return candidate as SteamPlayerSummary;
}
