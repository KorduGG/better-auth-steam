import assert from 'node:assert/strict';
import test from 'node:test';

import {
	fetchSteamPlayerSummary,
	verifySteamOpenIDResponse
} from '../src/steam/openid.ts';

const EXPECTED_RETURN_TO = 'https://example.com/api/auth/callback/steam';
const STEAM_ID = '76561198000000000';
const VALID_DIRECT_RESPONSE =
	'ns:http://specs.openid.net/auth/2.0\nis_valid:true\n';

function currentResponseNonce(suffix = 'abc123'): string {
	return `${new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')}${suffix}`;
}

function validOpenIDResponse(
	overrides: Record<string, string> = {}
): URLSearchParams {
	return new URLSearchParams({
		'openid.ns': 'http://specs.openid.net/auth/2.0',
		'openid.mode': 'id_res',
		'openid.op_endpoint': 'https://steamcommunity.com/openid/login',
		'openid.claimed_id': `https://steamcommunity.com/openid/id/${STEAM_ID}`,
		'openid.identity': `https://steamcommunity.com/openid/id/${STEAM_ID}`,
		'openid.return_to': EXPECTED_RETURN_TO,
		'openid.response_nonce': currentResponseNonce(),
		'openid.assoc_handle': '1234567890',
		'openid.signed':
			'op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle',
		'openid.sig': 'c2lnbmF0dXJl',
		...overrides
	});
}

function responseWithout(name: string): URLSearchParams {
	const params = validOpenIDResponse();
	params.delete(name);
	return params;
}

test('verifies an HTTPS Steam claimed ID', async (context) => {
	context.mock.method(globalThis, 'fetch', async () =>
		new Response(VALID_DIRECT_RESPONSE)
	);

	const params = validOpenIDResponse();
	const verification = await verifySteamOpenIDResponse(params, EXPECTED_RETURN_TO);

	assert.deepEqual(verification, {
		responseNonce: params.get('openid.response_nonce'),
		responseNonceExpiresAt: new Date(
			Date.parse(params.get('openid.response_nonce')!.slice(0, 20)) +
				10 * 60 * 1000
		),
		steamId: STEAM_ID
	});
});

test('rejects an HTTP Steam claimed ID', async () => {
	const claimedId = `http://steamcommunity.com/openid/id/${STEAM_ID}`;

	await assert.rejects(
		verifySteamOpenIDResponse(
			validOpenIDResponse({
				'openid.claimed_id': claimedId,
				'openid.identity': claimedId
			}),
			EXPECTED_RETURN_TO
		),
		/Invalid openid.claimed_id format/
	);
});

test('rejects invalid Steam claimed IDs', async (context) => {
	for (const claimedId of [
		`https://steamcommunity.com.example/openid/id/${STEAM_ID}`,
		`https://steamcommunity.com@evil.example/openid/id/${STEAM_ID}`,
		`https://steamcommunity.com/openid/user/${STEAM_ID}`,
		'https://steamcommunity.com/openid/id/not-a-number',
		`https://steamcommunity.com/openid/id/${STEAM_ID}/`
	]) {
		await context.test(claimedId, async () => {
			await assert.rejects(
				verifySteamOpenIDResponse(
					validOpenIDResponse({
						'openid.claimed_id': claimedId,
						'openid.identity': claimedId
					}),
					EXPECTED_RETURN_TO
				),
				/Invalid openid.claimed_id format/
			);
		});
	}
});

test('rejects a return URL that differs from the expected callback URL', async () => {
	await assert.rejects(
		verifySteamOpenIDResponse(
			validOpenIDResponse({
				'openid.return_to': `${EXPECTED_RETURN_TO}?redirect=/attacker`
			}),
			EXPECTED_RETURN_TO
		),
		/Invalid openid.return_to/
	);
});

test('rejects duplicate OpenID fields', async () => {
	const params = validOpenIDResponse();
	params.append('openid.return_to', 'https://attacker.example/callback');

	await assert.rejects(
		verifySteamOpenIDResponse(params, EXPECTED_RETURN_TO),
		/Duplicate OpenID field: openid.return_to/
	);
});

test('rejects invalid OpenID response metadata', async (context) => {
	const cases: Array<[string, URLSearchParams, RegExp]> = [
		[
			'namespace',
			validOpenIDResponse({ 'openid.ns': 'http://specs.openid.net/auth/1.1' }),
			/Invalid openid.ns/
		],
		[
			'mode',
			validOpenIDResponse({ 'openid.mode': 'cancel' }),
			/Invalid openid.mode/
		],
		[
			'provider endpoint',
			validOpenIDResponse({
				'openid.op_endpoint': 'https://steamcommunity.com.example/openid/login'
			}),
			/Invalid openid.op_endpoint/
		],
		[
			'identity',
			validOpenIDResponse({
				'openid.identity': 'https://steamcommunity.com/openid/id/76561198000000001'
			}),
			/Invalid openid.identity/
		],
		['response nonce', responseWithout('openid.response_nonce'), /Missing openid.response_nonce/],
		['association handle', responseWithout('openid.assoc_handle'), /Missing openid.assoc_handle/],
		['signed field list', responseWithout('openid.signed'), /Missing openid.signed/],
		['signature', responseWithout('openid.sig'), /Missing openid.sig/]
	];

	for (const [name, params, expectedError] of cases) {
		await context.test(name, async () => {
			await assert.rejects(
				verifySteamOpenIDResponse(params, EXPECTED_RETURN_TO),
				expectedError
			);
		});
	}
});

test('rejects an assertion that does not sign every required field', async (context) => {
	context.mock.method(globalThis, 'fetch', async () =>
		new Response(VALID_DIRECT_RESPONSE)
	);
	const requiredSignedFields = [
		'op_endpoint',
		'claimed_id',
		'identity',
		'return_to',
		'response_nonce',
		'assoc_handle'
	];

	for (const missingField of requiredSignedFields) {
		await context.test(missingField, async () => {
			const signedFields = requiredSignedFields.filter(
				(field) => field !== missingField
			);
			await assert.rejects(
				verifySteamOpenIDResponse(
					validOpenIDResponse({ 'openid.signed': signedFields.join(',') }),
					EXPECTED_RETURN_TO
				),
				new RegExp(`Missing signed OpenID field: ${missingField}`)
			);
		});
	}
});

test('sends the exact assertion fields for direct verification', async (context) => {
	let requestURL: string | URL | Request | undefined;
	let requestInit: RequestInit | undefined;
	context.mock.method(
		globalThis,
		'fetch',
		async (url: string | URL | Request, init?: RequestInit) => {
			requestURL = url;
			requestInit = init;
			return new Response(VALID_DIRECT_RESPONSE);
		}
	);
	const params = validOpenIDResponse({
		'openid.invalidate_handle': 'old-association'
	});
	params.set('state', 'application-state');

	await verifySteamOpenIDResponse(params, EXPECTED_RETURN_TO);

	assert.equal(requestURL, 'https://steamcommunity.com/openid/login');
	assert.equal(requestInit?.method, 'POST');
	assert.equal(requestInit?.redirect, 'error');
	assert.ok(requestInit?.signal instanceof AbortSignal);
	const sentParams = new URLSearchParams(String(requestInit?.body));
	const expectedParams = new URLSearchParams(
		[...params].filter(([key]) => key.startsWith('openid.'))
	);
	expectedParams.set('openid.mode', 'check_authentication');
	assert.deepEqual([...sentParams], [...expectedParams]);
});

test('requires HTTP 200 for direct verification', async (context) => {
	for (const status of [201, 500]) {
		await context.test(String(status), async (childContext) => {
			childContext.mock.method(globalThis, 'fetch', async () =>
				new Response(VALID_DIRECT_RESPONSE, { status })
			);
			await assert.rejects(
				verifySteamOpenIDResponse(validOpenIDResponse(), EXPECTED_RETURN_TO),
				new RegExp(`Steam OpenID error: ${status}`)
			);
		});
	}
});

test('requires an unambiguous OpenID 2.0 verification result', async (context) => {
	for (const body of [
		'is_valid:true\n',
		'ns:http://specs.openid.net/auth/1.1\nis_valid:true\n',
		'ns:http://specs.openid.net/auth/2.0\nnot_is_valid:true\n',
		'ns:http://specs.openid.net/auth/2.0\nis_valid:trueish\n',
		'ns:http://specs.openid.net/auth/2.0\nis_valid:false\nis_valid:true\n'
	]) {
		await context.test(body.trim(), async (childContext) => {
			childContext.mock.method(globalThis, 'fetch', async () => new Response(body));
			await assert.rejects(
				verifySteamOpenIDResponse(validOpenIDResponse(), EXPECTED_RETURN_TO),
				/(Steam OpenID verification failed|Duplicate Steam OpenID verification field)/
			);
		});
	}
});

test('rejects an invalid or stale response nonce', async (context) => {
	for (const nonce of [
		'not-a-nonce',
		'2026-02-31T08:00:00Zinvalid-date',
		'2020-01-01T00:00:00Zstale',
		`${new Date().toISOString()}fractional`,
		`${currentResponseNonce()} ${'x'.repeat(256)}`
	]) {
		await context.test(nonce.slice(0, 40), async () => {
			await assert.rejects(
				verifySteamOpenIDResponse(
					validOpenIDResponse({ 'openid.response_nonce': nonce }),
					EXPECTED_RETURN_TO
				),
				/Invalid openid.response_nonce/
			);
		});
	}
});

test('fetches a Steam profile with redirect and timeout controls', async (context) => {
	let requestURL: string | URL | Request | undefined;
	let requestInit: RequestInit | undefined;
	context.mock.method(
		globalThis,
		'fetch',
		async (url: string | URL | Request, init?: RequestInit) => {
			requestURL = url;
			requestInit = init;
			return Response.json({
				response: {
					players: [
						{
							steamid: STEAM_ID,
							personaname: 'Ada',
							avatarfull: 'https://example.com/avatar.jpg',
							profileurl: `https://steamcommunity.com/profiles/${STEAM_ID}`
						}
					]
				}
			});
		}
	);

	await fetchSteamPlayerSummary(STEAM_ID, 'key & value');

	assert.equal(
		requestURL,
		`https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=key%20%26%20value&steamids=${STEAM_ID}`
	);
	assert.equal(requestInit?.redirect, 'error');
	assert.ok(requestInit?.signal instanceof AbortSignal);
});

test('rejects a profile for a different Steam identity', async (context) => {
	context.mock.method(globalThis, 'fetch', async () =>
		Response.json({
			response: {
				players: [
					{
						steamid: '76561198000000001',
						personaname: 'Mallory',
						avatarfull: 'https://example.com/avatar.jpg',
						profileurl: 'https://steamcommunity.com/profiles/76561198000000001'
					}
				]
			}
		})
	);

	await assert.rejects(
		fetchSteamPlayerSummary(STEAM_ID, 'api-key'),
		/Steam profile identity mismatch/
	);
});

test('rejects malformed Steam profiles', async (context) => {
	for (const player of [
		{ steamid: STEAM_ID },
		{
			steamid: STEAM_ID,
			personaname: 123,
			avatarfull: 'https://example.com/avatar.jpg',
			profileurl: `https://steamcommunity.com/profiles/${STEAM_ID}`
		}
	]) {
		await context.test(JSON.stringify(player), async (childContext) => {
			childContext.mock.method(globalThis, 'fetch', async () =>
				Response.json({ response: { players: [player] } })
			);
			await assert.rejects(
				fetchSteamPlayerSummary(STEAM_ID, 'api-key'),
				/Invalid Steam profile response/
			);
		});
	}
});
