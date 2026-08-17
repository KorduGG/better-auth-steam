import { HIDE_METADATA, type BetterAuthPlugin } from 'better-auth';
import { APIError, createAuthEndpoint, sessionMiddleware } from 'better-auth/api';
import { generateState, handleOAuthUserInfo, parseState } from 'better-auth/oauth2';
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
import { addErrorToRedirect, normalizeRedirectTarget } from './redirect';
import type { SteamPluginOptions } from './types';

export const PROVIDER_ID = 'steam';

type SteamErrorCode = keyof typeof STEAM_ERROR_CODES;

const OAUTH_ERROR_CODES: Record<string, SteamErrorCode> = {
	'account not linked': 'STEAM_ACCOUNT_NOT_LINKED',
	'unable to link account': 'STEAM_UNABLE_TO_LINK_ACCOUNT',
	'unable to create user': 'STEAM_UNABLE_TO_CREATE_USER',
	'unable to create session': 'STEAM_UNABLE_TO_CREATE_SESSION'
};

const STATE_ERROR_CODES = new Set([
	'internal_server_error',
	'state_generation_error',
	'state_invalid',
	'state_mismatch',
	'state_not_found'
]);

const steamRateLimit = {
	pathMatcher: (path: string) => path.startsWith('/steam/'),
	window: 60,
	max: 10
};

/**
 * This Better Auth plugin adds Steam sign-in through Steam's OpenID 2.0 flow.
 *
 * The plugin provides these endpoints:
 *  - `POST /steam/login` starts Steam sign-in.
 *  - `POST /steam/link` starts authenticated account linking.
 *  - `GET /steam/callback` handles the Steam response.
 *
 * It stores SteamID64 in the `account` table and copies it to `user.steamId`.
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
					method: 'POST',
					body: z.object({
						callbackURL: z.string().optional(),
						errorCallbackURL: z.string().optional()
					}),
					requireHeaders: true,
					requireRequest: true,
					metadata: {
						openapi: {
							description: 'Redirect the user to Steam for OpenID authentication',
							responses: {
								'200': { description: 'The response contains the Steam OpenID login URL.' }
							}
						}
					}
				},
				async (ctx) => {
					const isTrustedRedirect = (url: string, settings?: { allowRelativePaths: boolean }) =>
						ctx.context.isTrustedOrigin(url, settings);
					const callbackURL = normalizeRedirectTarget(
						ctx.body.callbackURL,
						ctx.context.baseURL,
						'/',
						isTrustedRedirect
					);
					const errorCallbackURL = normalizeRedirectTarget(
						ctx.body.errorCallbackURL,
						ctx.context.baseURL,
						`${ctx.context.baseURL}/error`,
						isTrustedRedirect
					);
					const realm = new URL(ctx.context.baseURL).origin;
					const callbackEndpoint = `${ctx.context.baseURL}/steam/callback`;
					ctx.body.callbackURL = callbackURL;
					ctx.body.errorCallbackURL = errorCallbackURL;
					const { state } = await generateState(ctx, undefined, {
						returnTo: callbackEndpoint
					});
					const returnTo = new URL(callbackEndpoint);
					returnTo.searchParams.set('state', state);

					const url = buildSteamOpenIDRedirectURL(realm, returnTo.toString());
					ctx.setHeader('Location', url);
					return ctx.json({
						url,
						redirect: true
					});
				}
			),

			linkSteamAccount: createAuthEndpoint(
				'/steam/link',
				{
					method: 'POST',
					body: z.object({
						callbackURL: z.string().optional(),
						errorCallbackURL: z.string().optional()
					}),
					requireHeaders: true,
					requireRequest: true,
					use: [sessionMiddleware],
					metadata: {
						openapi: {
							description: 'Link Steam to the authenticated user',
							responses: {
								'200': { description: 'The response contains the Steam account-link URL.' }
							}
						}
					}
				},
				async (ctx) => {
					const linking = ctx.context.options.account?.accountLinking;
					if (linking?.enabled === false) {
						throw APIError.from(
							'BAD_REQUEST',
							STEAM_ERROR_CODES.STEAM_ACCOUNT_LINKING_DISABLED
						);
					}
					if (linking?.allowDifferentEmails !== true) {
						throw APIError.from(
							'BAD_REQUEST',
							STEAM_ERROR_CODES.STEAM_DIFFERENT_EMAIL_LINKING_DISABLED
						);
					}

					const isTrustedRedirect = (url: string, settings?: { allowRelativePaths: boolean }) =>
						ctx.context.isTrustedOrigin(url, settings);
					ctx.body.callbackURL = normalizeRedirectTarget(
						ctx.body.callbackURL,
						ctx.context.baseURL,
						'/',
						isTrustedRedirect
					);
					ctx.body.errorCallbackURL = normalizeRedirectTarget(
						ctx.body.errorCallbackURL,
						ctx.context.baseURL,
						`${ctx.context.baseURL}/error`,
						isTrustedRedirect
					);
					const realm = new URL(ctx.context.baseURL).origin;
					const callbackEndpoint = `${ctx.context.baseURL}/steam/callback`;
					const { state } = await generateState(
						ctx,
						{
							email: ctx.context.session.user.email,
							userId: ctx.context.session.user.id
						},
						{ returnTo: callbackEndpoint }
					);
					const returnTo = new URL(callbackEndpoint);
					returnTo.searchParams.set('state', state);

					const url = buildSteamOpenIDRedirectURL(realm, returnTo.toString());
					ctx.setHeader('Location', url);
					return ctx.json({
						url,
						redirect: true
					});
				}
			),

			steamCallback: createAuthEndpoint(
				'/steam/callback',
				{
					method: 'GET',
					query: z.object({ state: z.string() }),
					requireRequest: true,
					metadata: {
						...HIDE_METADATA,
						openapi: {
							description: 'Steam OpenID callback',
							responses: {
								'302': { description: 'The endpoint redirects to the original callback URL.' }
							}
						}
					}
				},
				async (ctx) => {
					const isTrustedRedirect = (url: string, settings?: { allowRelativePaths: boolean }) =>
						ctx.context.isTrustedOrigin(url, settings);
					const defaultErrorURL = normalizeRedirectTarget(
						ctx.context.options.onAPIError?.errorURL,
						ctx.context.baseURL,
						`${ctx.context.baseURL}/error`,
						isTrustedRedirect
					);
					const redirectWithError = (target: string, code: SteamErrorCode): never => {
						throw ctx.redirect(addErrorToRedirect(target, code, ctx.context.baseURL));
					};

					let stateData: Awaited<ReturnType<typeof parseState>>;
					try {
						stateData = await parseState(ctx);
					} catch (error) {
						let code = 'state_mismatch';
						let target = defaultErrorURL;
						if (error && typeof error === 'object' && 'headers' in error) {
							const headers = (error as { headers?: HeadersInit }).headers;
							const location = headers
								? new Headers(headers).get('location')
								: null;
							let stateErrorMatch: RegExpExecArray | undefined;
							for (const match of location?.matchAll(/[?&]error=([^&#]+)/g) ?? []) {
								let parsedCode: string;
								try {
									parsedCode = decodeURIComponent(match[1]);
								} catch {
									continue;
								}
								if (STATE_ERROR_CODES.has(parsedCode)) {
									code = parsedCode;
									stateErrorMatch = match;
								}
							}
							if (location && stateErrorMatch) {
								target = normalizeRedirectTarget(
									location.slice(0, stateErrorMatch.index),
									ctx.context.baseURL,
									defaultErrorURL,
									isTrustedRedirect
								);
							}
						}
						throw ctx.redirect(
							addErrorToRedirect(target, code, ctx.context.baseURL)
						);
					}

					const errorRedirectBase = normalizeRedirectTarget(
						stateData.errorURL,
						ctx.context.baseURL,
						defaultErrorURL,
						isTrustedRedirect
					);
					const callbackURL = normalizeRedirectTarget(
						stateData.callbackURL,
						ctx.context.baseURL,
						'/',
						isTrustedRedirect
					);
					const returnTo = new URL(String(stateData.returnTo));
					returnTo.searchParams.set('state', ctx.query.state);

					let steamId: string;
					try {
						const params = new URL(ctx.request.url).searchParams;
						steamId = await verifySteamOpenIDResponse(params, returnTo.toString());
					} catch (e) {
						ctx.context.logger.error('Steam OpenID verification failed.', e);
						return redirectWithError(errorRedirectBase, 'STEAM_VERIFICATION_FAILED');
					}

					let defaultName = `Steam User ${steamId}`;
					let defaultImage: string | undefined;
					let profile: Awaited<ReturnType<typeof fetchSteamPlayerSummary>> | undefined;
					try {
						profile = await fetchSteamPlayerSummary(steamId, options.apiKey);
						defaultName = profile.personaname;
						defaultImage = profile.avatarfull;
					} catch (e) {
						ctx.context.logger.warn(
							'Steam Web API is unavailable. The plugin uses the default profile.',
							e
						);
					}

					const profileOverrides = profile
						? options.mapProfileToUser?.(profile)
						: undefined;
					const name = profileOverrides?.name ?? defaultName;
					const image =
						profileOverrides?.image === undefined
							? defaultImage
							: profileOverrides.image;
					const email = profileOverrides?.email ?? `steam_${steamId}@${emailDomain}`;
					const link = stateData.link;
					if (link) {
						const linking = ctx.context.options.account?.accountLinking;
						if (linking?.enabled === false) {
							return redirectWithError(
								errorRedirectBase,
								'STEAM_ACCOUNT_LINKING_DISABLED'
							);
						}
						if (linking?.allowDifferentEmails !== true) {
							return redirectWithError(
								errorRedirectBase,
								'STEAM_DIFFERENT_EMAIL_LINKING_DISABLED'
							);
						}

						const existingAccount =
							await ctx.context.internalAdapter.findAccountByProviderId(
								steamId,
								PROVIDER_ID
							);
						if (existingAccount && existingAccount.userId.toString() !== link.userId) {
							return redirectWithError(errorRedirectBase, 'STEAM_ACCOUNT_ALREADY_LINKED');
						}
						let createdAccount: { id: string } | undefined;
						try {
							if (!existingAccount) {
								createdAccount = await ctx.context.internalAdapter.createAccount({
									userId: link.userId,
									providerId: PROVIDER_ID,
									accountId: steamId
								});
								if (!createdAccount) {
									return redirectWithError(
										errorRedirectBase,
										'STEAM_UNABLE_TO_LINK_ACCOUNT'
									);
								}
							}
							const updatedUser = await ctx.context.internalAdapter.updateUser(
								link.userId,
								{ steamId }
							);
							if (!updatedUser) {
								throw new Error('The user update did not complete.');
							}
						} catch (error) {
							ctx.context.logger.error('Steam account linking failed.', error);
							if (createdAccount) {
								await ctx.context.internalAdapter
									.deleteAccount(createdAccount.id)
									.catch((cleanupError) => {
										ctx.context.logger.error(
											'The plugin could not remove a partial Steam account link.',
											cleanupError
										);
									});
							}
							return redirectWithError(
								errorRedirectBase,
								'STEAM_UNABLE_TO_LINK_ACCOUNT'
							);
						}
						throw ctx.redirect(callbackURL);
					}

					let result: Awaited<ReturnType<typeof handleOAuthUserInfo>>;
					try {
						result = await handleOAuthUserInfo(ctx, {
							userInfo: {
								id: steamId,
								email,
								name,
								image,
								emailVerified: false,
								steamId
							} as Parameters<typeof handleOAuthUserInfo>[1]['userInfo'],
							account: {
								providerId: PROVIDER_ID,
								accountId: steamId
							},
							callbackURL,
							trustProviderByName: false
						});
					} catch (error) {
						ctx.context.logger.error('Steam authentication failed.', error);
						return redirectWithError(
							errorRedirectBase,
							'STEAM_AUTHENTICATION_FAILED'
						);
					}

					if (result.error !== null) {
						ctx.context.logger.error('Steam login failed.', { error: result.error });
						return redirectWithError(
							errorRedirectBase,
							OAUTH_ERROR_CODES[result.error] ?? 'STEAM_AUTHENTICATION_FAILED'
						);
					}

					let authenticatedUser = result.data.user as typeof result.data.user & {
						steamId?: string | null;
					};
					if (authenticatedUser.steamId !== steamId) {
						const updatedUser = await ctx.context.internalAdapter.updateUser(
							authenticatedUser.id,
							{ steamId }
						);
						if (updatedUser) {
							authenticatedUser = updatedUser as typeof authenticatedUser;
						}
					}

					await setSessionCookie(ctx, {
						session: result.data.session,
						user: authenticatedUser
					});

					throw ctx.redirect(callbackURL);
				}
			)
		},
		rateLimit: [steamRateLimit],
		options,
		$ERROR_CODES: STEAM_ERROR_CODES
	} satisfies BetterAuthPlugin;
};

export type { SteamPluginOptions, SteamPlayerSummary } from './types';
export { STEAM_ERROR_CODES } from './error-codes';
