import type { SteamPlayerSummary } from './openid';
import type { InferOptionSchema } from 'better-auth';
import type { schema } from './schema';

export interface SteamPluginOptions {
	/**
	 * Steam Web API key.
	 * Get one from https://steamcommunity.com/dev/apikey.
	 */
	apiKey: string;

	/**
	 * The plugin uses this domain to create an email for new Steam users.
	 * Steam's OpenID does not provide email addresses, so the plugin
	 * creates one of the form `steam_{steamId}@{syntheticEmailDomain}`.
	 *
	 * @default "steam.invalid"
	 */
	syntheticEmailDomain?: string;

	/**
	 * Customize how a Steam profile maps onto the Better Auth user fields.
	 * The function runs after the plugin verifies the OpenID identity and
	 * fetches the Steam Web API profile.
	 *
	 * The returned fields override the defaults. Any fields you omit fall back
	 * to the plugin defaults (synthetic email, personaname, avatarfull).
	 */
	mapProfileToUser?: (profile: SteamPlayerSummary) => {
		name?: string;
		email?: string;
		image?: string | null;
	};

	/**
	 * Update an existing user's mapped Steam profile fields on each sign-in.
	 *
	 * @default false
	 */
	overrideUserInfoOnSignIn?: boolean;

	/**
	 * This option renames the `steamId` field or its user model.
	 */
	schema?: InferOptionSchema<typeof schema>;
}

export type { SteamPlayerSummary };
