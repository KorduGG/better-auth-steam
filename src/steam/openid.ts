const STEAM_OPENID_URL = 'https://steamcommunity.com/openid/login';
const STEAM_ID_REGEX = /^https:\/\/steamcommunity\.com\/openid\/id\/(\d+)$/;

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

export async function verifySteamOpenIDResponse(params: URLSearchParams): Promise<string> {
	const claimedId = params.get('openid.claimed_id');
	if (!claimedId) {
		throw new Error('Missing openid.claimed_id');
	}

	const match = claimedId.match(STEAM_ID_REGEX);
	if (!match) {
		throw new Error('Invalid openid.claimed_id format');
	}

	const verifyParams = new URLSearchParams();
	for (const [key, value] of params.entries()) {
		verifyParams.set(key, value);
	}
	verifyParams.set('openid.mode', 'check_authentication');

	const response = await fetch(STEAM_OPENID_URL, {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: verifyParams.toString()
	});

	const text = await response.text();
	if (!text.includes('is_valid:true')) {
		throw new Error('Steam OpenID verification failed');
	}

	return match[1];
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
	const response = await fetch(url);
	if (!response.ok) {
		throw new Error(`Steam API error: ${response.status}`);
	}
	const data = (await response.json()) as { response?: { players?: SteamPlayerSummary[] } };
	const player = data?.response?.players?.[0];
	if (!player) {
		throw new Error('Player not found in Steam API response');
	}
	return player;
}
