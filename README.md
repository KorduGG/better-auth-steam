# better-auth-steam

Steam OpenID 2.0 plugin for Better Auth.

It adds a Steam login flow via two endpoints:

- `GET /api/auth/steam/login?callbackURL=/...`
- `GET /api/auth/steam/callback`

## Install

```bash
pnpm add better-auth-steam
```

## Server usage

```ts
import { betterAuth } from 'better-auth/minimal';
import { steamOpenID } from 'better-auth-steam';

export const auth = betterAuth({
	// ...your Better Auth config
	plugins: [
		steamOpenID({
			apiKey: process.env.STEAM_API_KEY!
		})
	]
});
```

## Options

```ts
type SteamPluginOptions = {
	apiKey: string;
	syntheticEmailDomain?: string;
	mapProfileToUser?: (profile: SteamPlayerSummary) => {
		name?: string;
		email?: string;
		image?: string | null;
	};
	schema?: BetterAuthPluginDBSchema;
};
```

- `apiKey`: Steam Web API key from https://steamcommunity.com/dev/apikey
- `syntheticEmailDomain`: used to generate fallback emails, defaults to `steam.local`
- `mapProfileToUser`: optional mapping function for Steam profile fields
- `schema`: override or extend the plugin schema

## Client plugin

```ts
import { createAuthClient } from 'better-auth/client';
import { steamOpenIDClient } from 'better-auth-steam/client';

export const authClient = createAuthClient({
	plugins: [steamOpenIDClient()]
});
```

## Schema behavior

The plugin adds a nullable unique `steamId` field on the Better Auth `user` model.

- `account.providerId`: `steam`
- `account.accountId`: SteamID64
- `user.steamId`: SteamID64

## Security notes

- Callback and error callback redirects are normalized and restricted to the current app origin.
- OpenID assertions are validated against Steam using `check_authentication`.

## Development

```bash
pnpm install
pnpm run lint
pnpm run typecheck
pnpm run build
```
