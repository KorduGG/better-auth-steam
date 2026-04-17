import type { SteamPlayerSummary } from './openid';
import type { BetterAuthPluginDBSchema } from 'better-auth/db';

export interface SteamPluginOptions {
	/**
	 * Steam Web API key.
	 * Get one from https://steamcommunity.com/dev/apikey
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
	 * Runs after the OpenID identity is verified and the Steam Web API
	 * profile is fetched (if fetching succeeded).
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
	 * Override or extend the plugin's database schema.
	 * Allows renaming the `steamId` field or changing its table model name.
	 */
	schema?: BetterAuthPluginDBSchema;
}

export type { SteamPlayerSummary };
