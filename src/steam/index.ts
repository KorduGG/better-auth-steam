import type { BetterAuthPlugin } from 'better-auth';
import { createAuthEndpoint } from 'better-auth/api';
import { handleOAuthUserInfo } from 'better-auth/oauth2';
import { setSessionCookie } from 'better-auth/cookies';
import { mergeSchema } from 'better-auth/db';
import * as z from 'zod';

import {
	buildSteamOpenIDRedirectURL,
	verifySteamOpenIDResponse,
	fetchSteamPlayerSummary
} from './openid';
import { schema } from './schema';
import { STEAM_ERROR_CODES } from './error-codes';
import { normalizeRedirectTarget } from './redirect';
import type { SteamPluginOptions } from './types';

export const PROVIDER_ID = 'steam';

/**
 * Better Auth plugin that adds Steam as a login provider via Steam's OpenID 2.0 flow.
 *
 * Exposes two endpoints:
 *  - `GET /steam/login?callbackURL=...` — redirects to Steam
 *  - `GET /steam/callback` — verifies the OpenID response and creates/links a user + session
 *
 * The Steam ID is stored:
 *  - In the `account` table as `{ providerId: "steam", accountId: <steamId64> }`
 *  - Denormalized on the `user` table as `steamId` (for convenient queries)
 */
export const steamOpenID = (options: SteamPluginOptions) => {
	const emailDomain = options.syntheticEmailDomain ?? 'steam.local';

	return {
		id: 'steam-openid',
		schema: mergeSchema(schema, options.schema),
		endpoints: {
			signInWithSteam: createAuthEndpoint(
				'/steam/login',
				{
					method: 'GET',
					query: z.object({
						callbackURL: z.string().optional(),
						errorCallbackURL: z.string().optional()
					}),
					metadata: {
						openapi: {
							description: 'Redirect the user to Steam for OpenID authentication',
							responses: {
								'302': { description: 'Redirect to Steam OpenID login' }
							}
						}
					}
				},
				async (ctx) => {
					const callbackURL = normalizeRedirectTarget(
						ctx.query.callbackURL,
						ctx.context.baseURL,
						'/'
					);
					const errorCallbackURL = normalizeRedirectTarget(
						ctx.query.errorCallbackURL,
						ctx.context.baseURL,
						`${ctx.context.baseURL}/error`
					);
					const realm = ctx.context.baseURL.replace(/\/api\/auth\/?$/, '');
					const returnTo = `${ctx.context.baseURL}/steam/callback`;

					ctx.setCookie('steam_callback_url', callbackURL, {
						httpOnly: true,
						secure: realm.startsWith('https'),
						sameSite: 'lax',
						path: '/',
						maxAge: 600
					});

					ctx.setCookie('steam_error_callback_url', errorCallbackURL, {
						httpOnly: true,
						secure: realm.startsWith('https'),
						sameSite: 'lax',
						path: '/',
						maxAge: 600
					});

					throw ctx.redirect(buildSteamOpenIDRedirectURL(realm, returnTo));
				}
			),

			steamCallback: createAuthEndpoint(
				'/steam/callback',
				{
					method: 'GET',
					metadata: {
						openapi: {
							description: 'Steam OpenID callback',
							responses: {
								'302': { description: 'Redirect to the original callbackURL' }
							}
						}
					}
				},
				async (ctx) => {
					const defaultErrorURL =
						ctx.context.options.onAPIError?.errorURL ||
						`${ctx.context.baseURL}/error`;
					const errorRedirectBase = normalizeRedirectTarget(
						ctx.getCookie('steam_error_callback_url'),
						ctx.context.baseURL,
						defaultErrorURL
					);

					const callbackURL = normalizeRedirectTarget(
						ctx.getCookie('steam_callback_url'),
						ctx.context.baseURL,
						'/'
					);
					ctx.setCookie('steam_callback_url', '', { path: '/', maxAge: 0 });
					ctx.setCookie('steam_error_callback_url', '', { path: '/', maxAge: 0 });

					const redirectWithError = (code: string): never => {
						const joiner = errorRedirectBase.includes('?') ? '&' : '?';
						throw ctx.redirect(`${errorRedirectBase}${joiner}error=${code}`);
					};

					let steamId: string;
					try {
						const params = new URL(ctx.request!.url).searchParams;
						steamId = await verifySteamOpenIDResponse(params);
					} catch (e) {
						ctx.context.logger.error('Steam OpenID verification failed', e);
						return redirectWithError('STEAM_VERIFICATION_FAILED');
					}

					let defaultName = `Steam User ${steamId}`;
					let defaultImage: string | undefined;
					let profile: Awaited<ReturnType<typeof fetchSteamPlayerSummary>> | undefined;
					try {
						profile = await fetchSteamPlayerSummary(steamId, options.apiKey);
						defaultName = profile.personaname;
						defaultImage = profile.avatarfull;
					} catch (e) {
						ctx.context.logger.warn('Steam Web API unavailable, continuing with fallback profile', e);
					}

					const mapped = profile ? options.mapProfileToUser?.(profile) : undefined;
					const name = mapped?.name ?? defaultName;
					const image = mapped?.image ?? defaultImage;
					const email = mapped?.email ?? `steam_${steamId}@${emailDomain}`;

					const result = await handleOAuthUserInfo(ctx, {
						userInfo: {
							id: steamId,
							email,
							name,
							image,
							emailVerified: true,
							steamId
						} as Parameters<typeof handleOAuthUserInfo>[1]['userInfo'],
						account: {
							providerId: PROVIDER_ID,
							accountId: steamId
						},
						callbackURL
					});

					if (result.error !== null) {
						ctx.context.logger.error('Steam login failed', { error: result.error });
						return redirectWithError(result.error.split(' ').join('_'));
					}

					const authedUser = result.data.user as typeof result.data.user & {
						steamId?: string | null;
					};
					if (authedUser.steamId !== steamId) {
						await ctx.context.internalAdapter.updateUser(authedUser.id, { steamId });
					}

					await setSessionCookie(ctx, {
						session: result.data.session,
						user: result.data.user
					});

					throw ctx.redirect(callbackURL);
				}
			)
		},
		options,
		$ERROR_CODES: STEAM_ERROR_CODES
	} satisfies BetterAuthPlugin;
};

export type { SteamPluginOptions, SteamPlayerSummary } from './types';
export { STEAM_ERROR_CODES } from './error-codes';
