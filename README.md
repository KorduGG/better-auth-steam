# better-auth-steam

Steam OpenID 2.0 plugin for Better Auth 1.6.21 or later.

It adds a Steam sign-in and account-link flow:

- `POST /api/auth/steam/login`
- `POST /api/auth/steam/link`
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
	trustedOrigins: ['https://app.example.com'],
	account: {
		accountLinking: {
			allowDifferentEmails: true
		}
	},
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
	overrideUserInfoOnSignIn?: boolean;
	mapProfileToUser?: (profile: SteamPlayerSummary) => {
		name?: string;
		email?: string;
		image?: string | null;
	};
	schema?: {
		user?: {
			modelName?: string;
			fields?: { steamId?: string };
		};
	};
};
```

- `apiKey`: Steam Web API key from https://steamcommunity.com/dev/apikey
- `syntheticEmailDomain`: used to generate fallback emails, defaults to `steam.invalid`
- `overrideUserInfoOnSignIn`: update mapped profile fields for existing users, defaults to `false`
- `mapProfileToUser`: optional mapping function for Steam profile fields
- `schema`: rename the `steamId` field or the `user` model

## Client plugin

```ts
import { createAuthClient } from 'better-auth/client';
import { steamOpenIDClient } from 'better-auth-steam/client';

export const authClient = createAuthClient({
	plugins: [steamOpenIDClient()]
});

await authClient.steam.login({
	callbackURL: '/account',
	errorCallbackURL: '/sign-in'
});
```

The client follows the URL in the Better Auth redirect response.

The sign-in endpoint changed from `GET` to `POST`. Replace direct links to the
old endpoint with the client call or a `POST` request. The plugin also returns
stable `STEAM_*` error codes instead of raw internal error text.

## Link an account

Account linking requires an authenticated session. Steam does not provide an
email address, so Better Auth must permit links between different email
addresses.

```ts
await authClient.steam.link({
	callbackURL: '/settings/accounts',
	errorCallbackURL: '/settings/accounts'
});
```

## Schema behavior

The plugin adds a nullable unique `steamId` field on the Better Auth `user` model.

- `account.providerId`: `steam`
- `account.accountId`: SteamID64
- `user.steamId`: SteamID64

The plugin creates a synthetic email because Better Auth requires an email on
the user record. The plugin marks this email as unverified. Steam does not
provide or verify email addresses.

## Security notes

- Better Auth state binds each callback to the browser that started the flow.
- Callback URLs must match Better Auth `trustedOrigins` or use a relative path.
- The callback validates required OpenID fields, signed fields, the exact
  `return_to` URL, and the Steam identity before it creates a session.
- The plugin validates the assertion with Steam through `check_authentication`.
- The plugin reserves each accepted Steam response nonce to prevent replay
  across separate sign-in states.
- Steam requests use a 10-second timeout and do not follow redirects.
- Steam never uses implicit email-based account linking. Use the authenticated
  link endpoint to connect Steam to an existing user.

## Development

```bash
pnpm install
pnpm run lint
pnpm run test
pnpm run typecheck
pnpm run build
```
