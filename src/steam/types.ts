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
	 * Domain used to synthesize an email for new Steam users.
	 * Steam's OpenID does not provide email addresses, so the plugin
	 * creates one of the form `steam_{steamId}@{syntheticEmailDomain}`.
	 *
	 * @default "steam.local"
	 */
	syntheticEmailDomain?: string;

	/**
	 * Customize how a Steam profile maps onto the Better Auth user fields.
	 * The function runs after the OpenID identity is verified and the plugin
	 * fetches the Steam Web API profile.
	 *
	 * Returned fields override the defaults. Any fields you omit fall back
	 * to the plugin defaults (synthetic email, personaname, avatarfull).
	 */
	mapProfileToUser?: (profile: SteamPlayerSummary) => {
		name?: string;
		email?: string;
		image?: string | null;
	};

	/**
	 * Rename the `steamId` field or its user model.
	 */
	schema?: InferOptionSchema<typeof schema>;
}

export type { SteamPlayerSummary };
