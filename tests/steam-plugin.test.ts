import assert from 'node:assert/strict';
import test from 'node:test';

import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { APIError } from 'better-auth/api';
import { createAuthClient } from 'better-auth/client';

import { steamOpenIDClient } from '../src/steam/client.ts';
import { steamOpenID } from '../src/steam/index.ts';
import type { SteamPluginOptions } from '../src/steam/types.ts';

const BASE_URL = 'https://auth.example/api/auth';
const APP_URL = 'https://app.example/account';
const ERROR_URL = 'https://app.example/error?source=steam#login';

function currentResponseNonce(suffix = 'abc'): string {
	return `${new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')}${suffix}`;
}

const validSchemaOption: SteamPluginOptions['schema'] = {
	user: { modelName: 'member', fields: { steamId: 'steam_id' } }
};
const invalidSchemaOption: SteamPluginOptions['schema'] = {
	user: {
		fields: {
			// @ts-expect-error Better Auth schema options only rename fields.
			steamId: { type: 'string' }
		}
	}
};
void invalidSchemaOption;

interface AuthOverrides {
	accountLinking?: {
		allowDifferentEmails?: boolean;
		enabled?: boolean;
		trustedProviders?: string[];
	};
	onAPIError?: { errorURL: string };
	rateLimit?: { enabled: boolean };
	session?: { cookieCache: { enabled: boolean; maxAge: number } };
	trustedOrigins?: string[];
}

function createAuth(
	plugin = steamOpenID({ apiKey: 'test-api-key' }),
	overrides: AuthOverrides = {}
) {
	const database: Record<string, unknown[]> = {
		account: [],
		rateLimit: [],
		session: [],
		user: [],
		verification: []
	};
	const auth = betterAuth({
		baseURL: BASE_URL,
		database: memoryAdapter(database),
		secret: 'steam-plugin-test-secret-that-is-at-least-32-characters',
		trustedOrigins: overrides.trustedOrigins ?? ['https://app.example'],
		onAPIError: overrides.onAPIError,
		rateLimit: overrides.rateLimit,
		session: overrides.session,
		emailAndPassword: { enabled: true },
		account: {
			accountLinking: overrides.accountLinking ?? {
				trustedProviders: ['steam'],
				allowDifferentEmails: true
			}
		},
		plugins: [plugin]
	});

	return { auth, database };
}

function cookieHeader(response: Response): string {
	return response.headers
		.getSetCookie()
		.map((value) => value.split(';', 1)[0])
		.join('; ');
}

async function startSignIn(
	auth: { handler: (request: Request) => Promise<Response> },
	requestBody: { callbackURL?: string; errorCallbackURL?: string } = {
		callbackURL: APP_URL,
		errorCallbackURL: ERROR_URL
	}
) {
	const response = await auth.handler(
		new Request(`${BASE_URL}/steam/login`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				origin: 'https://app.example'
			},
			body: JSON.stringify(requestBody)
		})
	);
	const responseBody = (await response.json()) as { redirect: boolean; url: string };
	const cookie = cookieHeader(response);

	return { body: responseBody, cookie, response };
}

async function signUp(
	auth: { handler: (request: Request) => Promise<Response> },
	email: string
): Promise<Response> {
	return auth.handler(
		new Request(`${BASE_URL}/sign-up/email`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				origin: 'https://app.example'
			},
			body: JSON.stringify({
				email,
				name: 'Test User',
				password: 'valid-password-123'
			})
		})
	);
}

async function startLink(
	auth: { handler: (request: Request) => Promise<Response> },
	sessionCookie: string
): Promise<Response> {
	return auth.handler(
		new Request(`${BASE_URL}/steam/link`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				cookie: sessionCookie,
				origin: 'https://app.example'
			},
			body: JSON.stringify({ callbackURL: APP_URL, errorCallbackURL: ERROR_URL })
		})
	);
}

function createCallbackURL(providerURL: string, steamId: string): URL {
	const provider = new URL(providerURL);
	const returnTo = provider.searchParams.get('openid.return_to')!;
	const callbackURL = new URL(returnTo);
	const claimedId = `http://steamcommunity.com/openid/id/${steamId}`;
	callbackURL.searchParams.set('openid.ns', 'http://specs.openid.net/auth/2.0');
	callbackURL.searchParams.set('openid.mode', 'id_res');
	callbackURL.searchParams.set(
		'openid.op_endpoint',
		'https://steamcommunity.com/openid/login'
	);
	callbackURL.searchParams.set('openid.claimed_id', claimedId);
	callbackURL.searchParams.set('openid.identity', claimedId);
	callbackURL.searchParams.set('openid.return_to', returnTo);
	callbackURL.searchParams.set(
		'openid.response_nonce',
		currentResponseNonce()
	);
	callbackURL.searchParams.set('openid.assoc_handle', 'handle');
	callbackURL.searchParams.set(
		'openid.signed',
		'op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle'
	);
	callbackURL.searchParams.set('openid.sig', 'c2lnbmF0dXJl');

	return callbackURL;
}

function mockSteam(context: test.TestContext, steamId: string) {
	context.mock.method(
		globalThis,
		'fetch',
		async (input: string | URL | Request) => {
			const url = String(input);
			if (url === 'https://steamcommunity.com/openid/login') {
				return new Response(
					'ns:http://specs.openid.net/auth/2.0\nis_valid:true\n'
				);
			}

			return Response.json({
				response: {
					players: [
						{
							steamid: steamId,
							personaname: 'Steam User',
							avatarfull: 'https://cdn.example/avatar.jpg',
							profileurl: 'https://steamcommunity.com/id/test'
						}
					]
				}
			});
		}
	);
}

test('starts Steam sign-in with request-bound redirect state', async () => {
	const { auth, database } = createAuth();
	const { body, response } = await startSignIn(auth);

	assert.equal(response.status, 200);
	assert.equal(body.redirect, true);
	assert.equal(response.headers.get('location'), body.url);

	const steamURL = new URL(body.url);
	const returnTo = new URL(steamURL.searchParams.get('openid.return_to')!);
	assert.equal(returnTo.origin + returnTo.pathname, `${BASE_URL}/steam/callback`);
	assert.ok(returnTo.searchParams.get('state'));

	assert.equal(database.verification.length, 1);
	const stateData = JSON.parse(
		(database.verification[0] as { value: string }).value
	) as { callbackURL: string; errorURL: string };
	assert.equal(stateData.callbackURL, APP_URL);
	assert.equal(stateData.errorURL, ERROR_URL);
});

test('signs in once with an unverified Steam identity', async (context) => {
	const plugin = steamOpenID({
		apiKey: 'test-api-key',
		mapProfileToUser: () => ({
			email: 'mapped-user@app.example',
			image: null
		})
	});
	const { auth, database } = createAuth(plugin);
	const { body, cookie } = await startSignIn(auth);
	const steamId = '76561198000000000';
	const callbackURL = createCallbackURL(body.url, steamId);
	mockSteam(context, steamId);

	const callbackResponse = await auth.handler(
		new Request(callbackURL, { headers: { cookie } })
	);
	assert.equal(callbackResponse.status, 302);
	assert.equal(callbackResponse.headers.get('location'), APP_URL);
	assert.equal(database.verification.length, 0);
	assert.equal(database.user.length, 1);
	assert.equal(database.account.length, 1);
	assert.equal(database.session.length, 1);
	assert.deepEqual(
		Object.fromEntries(
			Object.entries(database.user[0] as Record<string, unknown>).filter(([key]) =>
				['email', 'emailVerified', 'image', 'steamId'].includes(key)
			)
		),
		{
			email: 'mapped-user@app.example',
			emailVerified: false,
			image: null,
			steamId
		}
	);

	const replayResponse = await auth.handler(
		new Request(callbackURL, { headers: { cookie } })
	);
	assert.equal(replayResponse.status, 302);
	assert.equal(
		replayResponse.headers.get('location'),
		`${BASE_URL}/error?error=state_mismatch`
	);
	assert.equal(database.session.length, 1);
});

test('adds an error before the redirect fragment', async () => {
	const { auth } = createAuth();
	const { body, cookie } = await startSignIn(auth);
	const callbackURL = createCallbackURL(body.url, '76561198000000002');
	callbackURL.searchParams.delete('openid.sig');

	const response = await auth.handler(
		new Request(callbackURL, { headers: { cookie } })
	);
	assert.equal(response.status, 302);
	assert.equal(
		response.headers.get('location'),
		'https://app.example/error?source=steam&error=STEAM_VERIFICATION_FAILED#login'
	);
});

test('links Steam only through authenticated account-link state', async (context) => {
	const { auth, database } = createAuth();
	const signUpResponse = await signUp(auth, 'owner@app.example');
	assert.equal(signUpResponse.status, 200);
	const sessionCookie = cookieHeader(signUpResponse);
	const linkResponse = await startLink(auth, sessionCookie);
	assert.equal(linkResponse.status, 200);
	const linkBody = (await linkResponse.json()) as { url: string };
	assert.equal(linkResponse.headers.get('location'), linkBody.url);
	const stateCookie = cookieHeader(linkResponse);
	const steamId = '76561198000000001';
	const callbackURL = createCallbackURL(linkBody.url, steamId);
	mockSteam(context, steamId);

	const callbackResponse = await auth.handler(
		new Request(callbackURL, {
			headers: { cookie: `${sessionCookie}; ${stateCookie}` }
		})
	);
	assert.equal(callbackResponse.status, 302);
	assert.equal(callbackResponse.headers.get('location'), APP_URL);
	const steamAccount = database.account.find(
		(account) => (account as { providerId?: string }).providerId === 'steam'
	) as { accountId: string; userId: string } | undefined;
	assert.equal(steamAccount?.accountId, steamId);
	assert.equal(steamAccount?.userId, (database.user[0] as { id: string }).id);
	assert.equal((database.user[0] as { steamId: string }).steamId, steamId);
	assert.equal(database.session.length, 1);
});

test('does not link a verified local user through a mapped Steam email', async (context) => {
	const plugin = steamOpenID({
		apiKey: 'test-api-key',
		mapProfileToUser: () => ({ email: 'victim@app.example' })
	});
	const { auth, database } = createAuth(plugin);
	const signUpResponse = await signUp(auth, 'victim@app.example');
	assert.equal(signUpResponse.status, 200);
	(database.user[0] as { emailVerified: boolean }).emailVerified = true;

	const { body, cookie } = await startSignIn(auth);
	const steamId = '76561198000000003';
	const callbackURL = createCallbackURL(body.url, steamId);
	mockSteam(context, steamId);
	const response = await auth.handler(
		new Request(callbackURL, { headers: { cookie } })
	);

	assert.equal(response.status, 302);
	assert.equal(
		response.headers.get('location'),
		'https://app.example/error?source=steam&error=STEAM_ACCOUNT_NOT_LINKED#login'
	);
	assert.equal(
		database.account.some(
			(account) => (account as { providerId?: string }).providerId === 'steam'
		),
		false
	);
	assert.equal(database.session.length, 1);
});

test('rejects changed, expired, and foreign-browser state', async (context) => {
	await context.test('changed state', async () => {
		const { auth } = createAuth();
		const { body, cookie } = await startSignIn(auth);
		const callbackURL = createCallbackURL(body.url, '76561198000000004');
		callbackURL.searchParams.set('state', 'changed-state');
		const response = await auth.handler(
			new Request(callbackURL, { headers: { cookie } })
		);
		assert.equal(
			response.headers.get('location'),
			`${BASE_URL}/error?error=state_mismatch`
		);
	});

	await context.test('expired state', async () => {
		const { auth, database } = createAuth();
		const { body, cookie } = await startSignIn(auth);
		const verification = database.verification[0] as { value: string };
		const stateData = JSON.parse(verification.value) as { expiresAt: number };
		stateData.expiresAt = 0;
		verification.value = JSON.stringify(stateData);
		const callbackURL = createCallbackURL(body.url, '76561198000000005');
		const response = await auth.handler(
			new Request(callbackURL, { headers: { cookie } })
		);
		assert.equal(
			response.headers.get('location'),
			'https://app.example/error?source=steam&error=state_mismatch#login'
		);
	});

	await context.test('foreign browser', async () => {
		const { auth, database } = createAuth();
		const { body } = await startSignIn(auth);
		const callbackURL = createCallbackURL(body.url, '76561198000000006');
		const response = await auth.handler(new Request(callbackURL));
		assert.equal(
			response.headers.get('location'),
			'https://app.example/error?source=steam&error=state_mismatch#login'
		);
		assert.equal(database.verification.length, 1);
	});
});

test('rejects untrusted redirect targets', async () => {
	const { auth, database } = createAuth();
	const { response } = await startSignIn(auth, {
		callbackURL: 'https://evil.example/collect',
		errorCallbackURL: 'https://evil.example/error#capture'
	});

	assert.equal(response.status, 403);
	assert.equal(database.verification.length, 0);
});

test('preserves trusted relative redirect targets in state', async () => {
	const { auth, database } = createAuth();
	await startSignIn(auth, {
		callbackURL: '/account?source=steam',
		errorCallbackURL: '/sign-in?source=steam'
	});
	const stateData = JSON.parse(
		(database.verification[0] as { value: string }).value
	) as { callbackURL: string; errorURL: string };

	assert.equal(stateData.callbackURL, '/account?source=steam');
	assert.equal(stateData.errorURL, '/sign-in?source=steam');
});

test('uses a trusted fallback for invalid state errors', async () => {
	const { auth } = createAuth(steamOpenID({ apiKey: 'test-api-key' }), {
		onAPIError: { errorURL: 'https://evil.example/collect#fragment' }
	});
	const response = await auth.handler(
		new Request(`${BASE_URL}/steam/callback?state=invalid-state`)
	);

	assert.equal(
		response.headers.get('location'),
		`${BASE_URL}/error?error=state_mismatch`
	);
});

test('requires a session and enabled different-email linking', async (context) => {
	await context.test('missing session', async () => {
		const { auth } = createAuth();
		const response = await startLink(auth, '');
		assert.equal(response.status, 401);
	});

	for (const [name, accountLinking, code] of [
		[
			'disabled linking',
			{ enabled: false, allowDifferentEmails: true },
			'STEAM_ACCOUNT_LINKING_DISABLED'
		],
		[
			'different-email linking disabled',
			{ enabled: true, allowDifferentEmails: false },
			'STEAM_DIFFERENT_EMAIL_LINKING_DISABLED'
		]
	] as const) {
		await context.test(name, async () => {
			const { auth } = createAuth(steamOpenID({ apiKey: 'test-api-key' }), {
				accountLinking
			});
			const signUpResponse = await signUp(auth, `${name.replaceAll(' ', '-')}@app.example`);
			const response = await startLink(auth, cookieHeader(signUpResponse));
			const body = (await response.json()) as { code: string };
			assert.equal(response.status, 400);
			assert.equal(body.code, code);
		});
	}
});

test('rejects a Steam account that belongs to another user', async (context) => {
	const { auth, database } = createAuth();
	await signUp(auth, 'first-owner@app.example');
	const secondSignUp = await signUp(auth, 'second-owner@app.example');
	const steamId = '76561198000000007';
	database.account.push({
		id: 'existing-steam-account',
		accountId: steamId,
		providerId: 'steam',
		userId: (database.user[0] as { id: string }).id,
		createdAt: new Date(),
		updatedAt: new Date()
	});

	const linkResponse = await startLink(auth, cookieHeader(secondSignUp));
	const linkBody = (await linkResponse.json()) as { url: string };
	const callbackURL = createCallbackURL(linkBody.url, steamId);
	mockSteam(context, steamId);
	const response = await auth.handler(
		new Request(callbackURL, {
			headers: { cookie: cookieHeader(linkResponse) }
		})
	);

	assert.equal(
		response.headers.get('location'),
		'https://app.example/error?source=steam&error=STEAM_ACCOUNT_ALREADY_LINKED#login'
	);
	assert.equal(
		(database.user[1] as { steamId?: string }).steamId,
		undefined
	);
});

test('stores the updated Steam user in the session cookie cache', async (context) => {
	const { auth } = createAuth(steamOpenID({ apiKey: 'test-api-key' }), {
		session: { cookieCache: { enabled: true, maxAge: 300 } }
	});
	const { body, cookie } = await startSignIn(auth);
	const steamId = '76561198000000008';
	const callbackURL = createCallbackURL(body.url, steamId);
	mockSteam(context, steamId);
	const callbackResponse = await auth.handler(
		new Request(callbackURL, { headers: { cookie } })
	);
	const sessionResponse = await auth.handler(
		new Request(`${BASE_URL}/get-session`, {
			headers: { cookie: cookieHeader(callbackResponse) }
		})
	);
	const session = (await sessionResponse.json()) as { user: { steamId: string } };

	assert.equal(session.user.steamId, steamId);
});

test('uses the default profile when the Steam profile request fails', async (context) => {
	const { auth, database } = createAuth();
	const { body, cookie } = await startSignIn(auth);
	const steamId = '76561198000000009';
	const callbackURL = createCallbackURL(body.url, steamId);
	context.mock.method(globalThis, 'fetch', async (input: string | URL | Request) => {
		if (String(input) === 'https://steamcommunity.com/openid/login') {
			return new Response(
				'ns:http://specs.openid.net/auth/2.0\nis_valid:true\n'
			);
		}
		throw new DOMException('The request timed out.', 'TimeoutError');
	});

	const response = await auth.handler(
		new Request(callbackURL, { headers: { cookie } })
	);

	assert.equal(response.headers.get('location'), APP_URL);
	assert.equal(
		(database.user[0] as { name: string }).name,
		`Steam User ${steamId}`
	);
});

test('forces POST for empty client sign-in and link calls', async (context) => {
	const methods: string[] = [];
	context.mock.method(
		globalThis,
		'fetch',
		async (_input: string | URL | Request, init?: RequestInit) => {
		methods.push(init?.method ?? 'GET');
		return Response.json({ redirect: true, url: 'https://steamcommunity.com/' });
		}
	);
	const client = createAuthClient({
		baseURL: BASE_URL,
		disableDefaultFetchPlugins: true,
		plugins: [steamOpenIDClient()]
	});

	await client.steam.login();
	await client.steam.link();

	assert.deepEqual(methods, ['POST', 'POST']);
});

test('hides the callback and applies schema renames', () => {
	const plugin = steamOpenID({
		apiKey: 'test-api-key',
		schema: validSchemaOption
	});

	assert.equal(plugin.endpoints.steamCallback.options.metadata?.scope, 'server');
	const userSchema = plugin.schema.user as {
		modelName?: string;
		fields: { steamId: { fieldName?: string } };
	};
	assert.equal(userSchema.modelName, 'member');
	assert.equal(userSchema.fields.steamId.fieldName, 'steam_id');
});

test('rejects malformed OpenID assertions through the callback', async (context) => {
	const cases: Array<[string, (callbackURL: URL) => void]> = [
		[
			'changed return URL',
			(callbackURL) =>
				callbackURL.searchParams.set(
					'openid.return_to',
					`${BASE_URL}/steam/callback?state=attacker`
				)
		],
		[
			'lookalike provider endpoint',
			(callbackURL) =>
				callbackURL.searchParams.set(
					'openid.op_endpoint',
					'https://steamcommunity.com.example/openid/login'
				)
		],
		[
			'lookalike claimed ID',
			(callbackURL) => {
				const claimedId =
					'http://steamcommunity.com.example/openid/id/76561198000000010';
				callbackURL.searchParams.set('openid.claimed_id', claimedId);
				callbackURL.searchParams.set('openid.identity', claimedId);
			}
		],
		[
			'identity mismatch',
			(callbackURL) =>
				callbackURL.searchParams.set(
					'openid.identity',
					'http://steamcommunity.com/openid/id/76561198000000011'
				)
		],
		[
			'invalid nonce',
			(callbackURL) =>
				callbackURL.searchParams.set('openid.response_nonce', 'invalid')
		],
		[
			'fractional nonce',
			(callbackURL) =>
				callbackURL.searchParams.set(
					'openid.response_nonce',
					`${new Date().toISOString()}fractional`
				)
		],
		[
			'duplicate OpenID field',
			(callbackURL) =>
				callbackURL.searchParams.append('openid.sig', 'c2lnbmF0dXJl')
		]
	];

	for (const [name, modify] of cases) {
		await context.test(name, async () => {
			const { auth, database } = createAuth();
			const { body, cookie } = await startSignIn(auth);
			const callbackURL = createCallbackURL(body.url, '76561198000000010');
			modify(callbackURL);
			const response = await auth.handler(
				new Request(callbackURL, { headers: { cookie } })
			);
			assert.equal(
				response.headers.get('location'),
				'https://app.example/error?source=steam&error=STEAM_VERIFICATION_FAILED#login'
			);
			assert.equal(database.account.length, 0);
			assert.equal(database.session.length, 0);
		});
	}
});

test('rejects a callback without state', async () => {
	const { auth, database } = createAuth();
	const callbackURL = createCallbackURL(
		'https://steamcommunity.com/openid/login?openid.return_to=https%3A%2F%2Fauth.example%2Fapi%2Fauth%2Fsteam%2Fcallback',
		'76561198000000012'
	);
	callbackURL.searchParams.delete('state');
	const response = await auth.handler(new Request(callbackURL));

	assert.equal(response.status, 400);
	assert.equal(database.account.length, 0);
	assert.equal(database.session.length, 0);
});

test('fails closed when direct verification times out', async (context) => {
	const { auth, database } = createAuth();
	const { body, cookie } = await startSignIn(auth);
	const callbackURL = createCallbackURL(body.url, '76561198000000013');
	context.mock.method(globalThis, 'fetch', async () => {
		throw new DOMException('The request timed out.', 'TimeoutError');
	});

	const response = await auth.handler(
		new Request(callbackURL, { headers: { cookie } })
	);

	assert.equal(
		response.headers.get('location'),
		'https://app.example/error?source=steam&error=STEAM_VERIFICATION_FAILED#login'
	);
	assert.equal(database.account.length, 0);
	assert.equal(database.session.length, 0);
});

test('rejects ambiguous direct-verification responses through the callback', async (context) => {
	for (const body of [
		'is_valid:true\n',
		'ns:http://specs.openid.net/auth/2.0\nis_valid:false\nis_valid:true\n'
	]) {
		await context.test(body.trim(), async (childContext) => {
			const { auth, database } = createAuth();
			const { body: signInBody, cookie } = await startSignIn(auth);
			const callbackURL = createCallbackURL(
				signInBody.url,
				'76561198000000015'
			);
			childContext.mock.method(globalThis, 'fetch', async () => new Response(body));
			const response = await auth.handler(
				new Request(callbackURL, { headers: { cookie } })
			);

			assert.equal(
				response.headers.get('location'),
				'https://app.example/error?source=steam&error=STEAM_VERIFICATION_FAILED#login'
			);
			assert.equal(database.account.length, 0);
			assert.equal(database.session.length, 0);
		});
	}
});

test('uses the default profile for malformed Steam profile data', async (context) => {
	const { auth, database } = createAuth();
	const { body, cookie } = await startSignIn(auth);
	const steamId = '76561198000000016';
	const callbackURL = createCallbackURL(body.url, steamId);
	context.mock.method(globalThis, 'fetch', async (input: string | URL | Request) => {
		if (String(input) === 'https://steamcommunity.com/openid/login') {
			return new Response(
				'ns:http://specs.openid.net/auth/2.0\nis_valid:true\n'
			);
		}
		return Response.json({
			response: {
				players: [
					{
						steamid: steamId,
						personaname: 123,
						avatarfull: 'https://cdn.example/avatar.jpg',
						profileurl: 'https://steamcommunity.com/id/test'
					}
				]
			}
		});
	});

	const response = await auth.handler(
		new Request(callbackURL, { headers: { cookie } })
	);

	assert.equal(response.headers.get('location'), APP_URL);
	assert.equal(
		(database.user[0] as { name: string }).name,
		`Steam User ${steamId}`
	);
});

test('uses the Steam avatar when the profile mapper returns undefined', async (context) => {
	const plugin = steamOpenID({
		apiKey: 'test-api-key',
		mapProfileToUser: () => ({ image: undefined })
	});
	const { auth, database } = createAuth(plugin);
	const { body, cookie } = await startSignIn(auth);
	const steamId = '76561198000000014';
	const callbackURL = createCallbackURL(body.url, steamId);
	mockSteam(context, steamId);

	await auth.handler(new Request(callbackURL, { headers: { cookie } }));

	assert.equal(
		(database.user[0] as { image: string }).image,
		'https://cdn.example/avatar.jpg'
	);
});

test('rate limits Steam endpoints before provider work', async () => {
	const { auth, database } = createAuth(
		steamOpenID({ apiKey: 'test-api-key' }),
		{ rateLimit: { enabled: true } }
	);
	let response: Response | undefined;
	for (let index = 0; index < 11; index += 1) {
		response = await auth.handler(
			new Request(`${BASE_URL}/steam/login`, {
				method: 'POST',
				headers: {
					'content-type': 'application/json',
					origin: 'https://app.example',
					'x-forwarded-for': '192.0.2.1'
				},
				body: '{}'
			})
		);
	}

	assert.equal(response?.status, 429);
	assert.equal(database.verification.length, 10);
});

test('rate limits callbacks before state parsing', async () => {
	const { auth } = createAuth(
		steamOpenID({ apiKey: 'test-api-key' }),
		{ rateLimit: { enabled: true } }
	);
	let response: Response | undefined;
	for (let index = 0; index < 11; index += 1) {
		response = await auth.handler(
			new Request(`${BASE_URL}/steam/callback?state=invalid-${index}`, {
				headers: { 'x-forwarded-for': '192.0.2.2' }
			})
		);
	}

	assert.equal(response?.status, 429);
});

test('emits stable codes for account and session creation failures', async (context) => {
	await context.test('explicit account creation failure', async (childContext) => {
		const { auth } = createAuth();
		const signUpResponse = await signUp(auth, 'link-failure@app.example');
		const linkResponse = await startLink(auth, cookieHeader(signUpResponse));
		const linkBody = (await linkResponse.json()) as { url: string };
		const steamId = '76561198000000017';
		const callbackURL = createCallbackURL(linkBody.url, steamId);
		const adapter = (await auth.$context).internalAdapter;
		childContext.mock.method(adapter, 'createAccount', async () => {
			throw new Error('The test adapter rejected the account.');
		});
		mockSteam(childContext, steamId);

		const response = await auth.handler(
			new Request(callbackURL, {
				headers: { cookie: cookieHeader(linkResponse) }
			})
		);
		assert.equal(
			response.headers.get('location'),
			'https://app.example/error?source=steam&error=STEAM_UNABLE_TO_LINK_ACCOUNT#login'
		);
	});

	await context.test('explicit user update veto', async (childContext) => {
		const { auth, database } = createAuth();
		const signUpResponse = await signUp(auth, 'update-veto@app.example');
		const linkResponse = await startLink(auth, cookieHeader(signUpResponse));
		const linkBody = (await linkResponse.json()) as { url: string };
		const steamId = '76561198000000021';
		const callbackURL = createCallbackURL(linkBody.url, steamId);
		const adapter = (await auth.$context).internalAdapter;
		childContext.mock.method(adapter, 'updateUser', async () => null);
		mockSteam(childContext, steamId);

		const response = await auth.handler(
			new Request(callbackURL, {
				headers: { cookie: cookieHeader(linkResponse) }
			})
		);
		assert.equal(
			response.headers.get('location'),
			'https://app.example/error?source=steam&error=STEAM_UNABLE_TO_LINK_ACCOUNT#login'
		);
		assert.equal(
			database.account.some(
				(account) => (account as { providerId?: string }).providerId === 'steam'
			),
			false
		);
	});

	for (const [name, method, expectedCode] of [
		[
			'user creation failure',
			'createOAuthUser',
			'STEAM_UNABLE_TO_CREATE_USER'
		],
		[
			'session creation failure',
			'createSession',
			'STEAM_UNABLE_TO_CREATE_SESSION'
		],
		[
			'unknown authentication failure',
			'unknownOAuthError',
			'STEAM_AUTHENTICATION_FAILED'
		]
	] as const) {
		await context.test(name, async (childContext) => {
			const { auth } = createAuth();
			const { body, cookie } = await startSignIn(auth);
			const steamId = `765611980000000${method === 'createSession' ? '18' : method === 'createOAuthUser' ? '19' : '20'}`;
			const callbackURL = createCallbackURL(body.url, steamId);
			const adapter = (await auth.$context).internalAdapter;
			if (method === 'createSession') {
				childContext.mock.method(adapter, 'createSession', async () => null);
			} else if (method === 'createOAuthUser') {
				childContext.mock.method(adapter, 'createOAuthUser', async () => {
					throw new Error('The test adapter rejected the user.');
				});
			} else {
				childContext.mock.method(adapter, 'createOAuthUser', async () => {
					throw APIError.from('BAD_REQUEST', {
						code: 'UNKNOWN_OAUTH_ERROR',
						message: 'The test adapter returned an unknown OAuth error.'
					});
				});
			}
			mockSteam(childContext, steamId);

			const response = await auth.handler(
				new Request(callbackURL, { headers: { cookie } })
			);
			assert.equal(
				response.headers.get('location'),
				`https://app.example/error?source=steam&error=${expectedCode}#login`
			);
		});
	}
});

test('remaps OAuth helper redirects to a trusted error target', async (context) => {
	const { auth } = createAuth(steamOpenID({ apiKey: 'test-api-key' }), {
		onAPIError: { errorURL: 'https://evil.example/collect#fragment' }
	});
	const { body, cookie } = await startSignIn(auth);
	const steamId = '76561198000000022';
	const callbackURL = createCallbackURL(body.url, steamId);
	const adapter = (await auth.$context).internalAdapter;
	context.mock.method(adapter, 'findOAuthUser', async () => {
		throw new Error('The test adapter rejected the OAuth lookup.');
	});
	mockSteam(context, steamId);

	const response = await auth.handler(
		new Request(callbackURL, { headers: { cookie } })
	);

	assert.equal(
		response.headers.get('location'),
		'https://app.example/error?source=steam&error=STEAM_AUTHENTICATION_FAILED#login'
	);
});

test('declares only the public error codes that callback paths emit', () => {
	const plugin = steamOpenID({ apiKey: 'test-api-key' });
	assert.deepEqual(Object.keys(plugin.$ERROR_CODES).sort(), [
		'STEAM_ACCOUNT_ALREADY_LINKED',
		'STEAM_ACCOUNT_LINKING_DISABLED',
		'STEAM_ACCOUNT_NOT_LINKED',
		'STEAM_AUTHENTICATION_FAILED',
		'STEAM_DIFFERENT_EMAIL_LINKING_DISABLED',
		'STEAM_UNABLE_TO_CREATE_SESSION',
		'STEAM_UNABLE_TO_CREATE_USER',
		'STEAM_UNABLE_TO_LINK_ACCOUNT',
		'STEAM_VERIFICATION_FAILED'
	]);
});
