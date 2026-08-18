# Better Auth provider practices for Steam OpenID

Research date: 2026-08-17. The recommendations use Better Auth 1.6.29 as the current stable reference. They also use the OpenID 2.0 final specification and the Steamworks authentication documentation.

## Required design

1. Use a `POST` sign-in endpoint. A sign-in starts state and changes cookies, so the endpoint is not a read-only operation. Return `{ url, redirect: true }` and set the `Location` header. This is the same response contract as Better Auth social sign-in. Hide the provider callback from client inference with `HIDE_METADATA`. Set `requireRequest: true` on endpoints that need the real request, cookies, or response headers. Better Auth requires `POST` for operations that modify data, and its social sign-in returns the authorization URL and a `redirect` flag. [Plugin endpoint rules](https://better-auth.com/docs/concepts/plugins#endpoints), [social sign-in source](https://github.com/better-auth/better-auth/blob/v1.6.29/packages/better-auth/src/api/routes/sign-in.ts), [SIWE `requireRequest` example](https://github.com/better-auth/better-auth/blob/v1.6.29/packages/better-auth/src/plugins/siwe/index.ts), [OAuth callback metadata](https://github.com/better-auth/better-auth/blob/v1.6.29/packages/better-auth/src/api/routes/callback.ts).

2. Use Better Auth state helpers. Call `generateState` when sign-in starts. Put the returned state in `openid.return_to`, for example `/steam/callback?state=<state>`. Call `parseState` on the callback and use the returned `callbackURL` and `errorURL`. Do not store these URLs in unsigned, plugin-owned cookies. Better Auth state has a 10-minute lifetime, supports database or encrypted-cookie storage, and binds the callback to the browser with signed state. [OAuth state security](https://better-auth.com/docs/reference/security#oauth-state-and-pkce), [state errors and replay behavior](https://better-auth.com/docs/reference/errors/state_mismatch), [state helper source](https://github.com/better-auth/better-auth/blob/v1.6.29/packages/better-auth/src/oauth2/state.ts).

3. Validate each redirect with `ctx.context.isTrustedOrigin(url, { allowRelativePaths: true })`. This check supports the application `trustedOrigins` configuration and relative paths. Apply the same check to the normal callback URL, the new-user URL if one is added, the error URL, and the configured `onAPIError.errorURL`. Add error parameters with `URL.searchParams`; this keeps query data before a URL fragment. [Trusted-origin plugin guidance](https://better-auth.com/docs/concepts/plugins#trusted-origins), [SSO redirect security](https://better-auth.com/docs/plugins/sso#security).

4. Use Better Auth cookie helpers for all authentication cookies. Better Auth applies the configured prefix and the secure, `httpOnly`, and `SameSite` attributes. Prefer `generateState` and `parseState`, which already create and expire the correct state cookies. Do not duplicate cookie policy in the plugin. [Cookie behavior](https://better-auth.com/docs/concepts/cookies), [plugin `createAuthCookie` guidance](https://better-auth.com/docs/concepts/plugins#context-object).

5. Treat SteamID as the provider identity. Steam OpenID does not supply an email address. If Better Auth needs a synthetic email, mark the email as `emailVerified: false`. Set `trustProviderByName: false` when the plugin calls `handleOAuthUserInfo`. This setting prevents an application-level `trustedProviders` entry from turning a mapped or synthetic email into proof for implicit account linking. Returning users must match the `steam` provider account and SteamID. A separate account-link operation must require an authenticated session and state. Better Auth warns that trusted providers can increase account-takeover risk. Better Auth 1.6.11 fixed an implicit-link vulnerability. Better Auth 1.6.21 also moved rate limiting before plugin handlers and fixed forwarded-address spoofing. Set the package minimum to at least 1.6.21 when the plugin depends on both protections. [Steam OpenID data](https://partner.steamgames.com/doc/features/auth#user-authentication), [account-linking options](https://better-auth.com/docs/reference/options#account), [Better Auth core changelog](https://github.com/better-auth/better-auth/blob/main/packages/core/CHANGELOG.md#1611), [Better Auth package changelog](https://github.com/better-auth/better-auth/blob/main/packages/better-auth/CHANGELOG.md#1621).

6. Use `InferOptionSchema<typeof schema>` for the public `schema` option. This type permits only `modelName` and field-name overrides for the schema that the plugin owns. It does not promise arbitrary schema extension. Pass this option to `mergeSchema`. [Better Auth schema-option type](https://github.com/better-auth/better-auth/blob/v1.4.22/packages/better-auth/src/types/plugins.ts), [built-in SIWE option](https://github.com/better-auth/better-auth/blob/v1.6.29/packages/better-auth/src/plugins/siwe/index.ts), [plugin schema model](https://better-auth.com/docs/concepts/plugins#schema).

7. Keep one small, stable public error set. Every plugin-owned public error code must be emitted by a real path. Remove unused codes. Map internal Better Auth or Steam failures to stable plugin codes and keep the detailed cause in server logs. Do not create callback codes from arbitrary exception text. Better Auth plugins expose fixed error objects, and callbacks use fixed redirect codes. [Generic OAuth plugin source](https://github.com/better-auth/better-auth/blob/v1.6.29/packages/better-auth/src/plugins/generic-oauth/index.ts), [Better Auth callback source](https://github.com/better-auth/better-auth/blob/v1.6.29/packages/better-auth/src/api/routes/callback.ts).

8. Add plugin rate limits for the sign-in and callback paths. Both paths cause authentication work, and the callback also causes outbound calls. Better Auth 1.6 uses per-plugin `pathMatcher`, `window`, and `max` rules. [Plugin rate limits](https://better-auth.com/docs/concepts/plugins#rate-limit), [rate-limit defaults and behavior](https://better-auth.com/docs/concepts/rate-limit).

9. Add a finite timeout to the Steam OpenID verification request and the player-summary request. Better Auth does not define a provider timeout contract. The stable Generic OAuth implementation calls the fetch layer without a provider-specific timeout in the examined paths. Therefore, the timeout is a project defense, not a Better Auth compatibility rule. Convert a timeout into a stable verification or profile-fetch result. The profile request can fall back to the default profile, but OpenID verification must fail closed. [Generic OAuth provider implementation](https://github.com/better-auth/better-auth/blob/v1.6.29/packages/better-auth/src/plugins/generic-oauth/index.ts).

10. Pass the final user row to `setSessionCookie`. If the plugin adds `steamId` after `handleOAuthUserInfo`, use the user returned by `updateUser` when the session cookie is set. Otherwise, an enabled session cookie cache can contain the old user data. The built-in callback passes the same final `session` and `user` result to `setSessionCookie`. [Better Auth callback source](https://github.com/better-auth/better-auth/blob/v1.6.29/packages/better-auth/src/api/routes/callback.ts), [session cookie caching](https://better-auth.com/docs/concepts/session-management#session-caching).

11. Preserve an explicit `image: null` mapping. Use the Steam avatar only when the mapper returns `undefined`. A `null` value means that the user requested no image.

## OpenID 2.0 verification checklist

The callback must pass all checks before the plugin creates or links an account:

- Require `openid.ns` to equal `http://specs.openid.net/auth/2.0` and `openid.mode` to equal `id_res`.
- Require the Steam OP endpoint and identity data to match the fixed Steam provider configuration. Steam's documentation still lists `http://steamcommunity.com/openid/id/<steamid>`, but current provider responses use `https://steamcommunity.com/openid/id/<steamid>`. Accept only the exact HTTPS claimed-ID prefix. Reject the HTTP prefix. [Steamworks authentication documentation](https://partner.steamgames.com/doc/features/auth#user-authentication).
- Require `openid.return_to` to match the callback scheme, authority, path, and state query value. The current callback request can contain additional OpenID query fields, but every query field in `return_to` must have the same value in the request. [OpenID 2.0 section 11.1](https://openid.net/specs/openid-authentication-2_0.html#verify_return_to).
- Require `openid.identity` to equal the claimed ID for Steam. Require `openid.response_nonce`, `openid.assoc_handle`, `openid.signed`, and `openid.sig`.
- Parse `openid.signed` as a comma-separated set. Require `op_endpoint`, `return_to`, `response_nonce`, `assoc_handle`, `claimed_id`, and `identity`. The specification requires these fields to be signed when the identity fields are present. [OpenID 2.0 positive assertions](https://openid.net/specs/openid-authentication-2_0.html#positive_assertions).
- Send a direct `POST` to the OP with exact copies of the OpenID response fields, except change `openid.mode` to `check_authentication`. Exclude application query fields such as `state`. Require HTTP 200. Parse the key-value response exactly, require the OpenID namespace, and require one `is_valid:true` field; do not use a substring test. [OpenID 2.0 direct verification request](https://openid.net/specs/openid-authentication-2_0.html#check_auth), [direct verification response](https://openid.net/specs/openid-authentication-2_0.html#anchor28).
- Prevent replay. The OpenID specification requires the relying party to reject an accepted nonce from the same OP. Direct verification also requires the OP not to validate the same response nonce twice. Better Auth state is single-use and adds a browser-bound replay check. [OpenID 2.0 section 11.3](https://openid.net/specs/openid-authentication-2_0.html#verify_nonce), [Better Auth state behavior](https://better-auth.com/docs/reference/errors/state_mismatch).

OpenID 2.0 says that a positive assertion is valid only after the return URL, discovered information, nonce, signature, and required signed fields pass verification. [OpenID 2.0 section 11](https://openid.net/specs/openid-authentication-2_0.html#verification).

## Required tests

Use integration tests through `auth.handler` or an equivalent real request path. Use Better Auth test utilities only in a test auth instance. [Better Auth test utilities](https://better-auth.com/docs/plugins/test-utils).

At minimum, test these cases:

- The sign-in route is `POST` and returns `{ url, redirect: true }`.
- A valid flow sets Better Auth state, accepts the matching callback once, creates the `steam` account, sets a session cookie, and redirects to the trusted callback.
- Missing, changed, expired, or replayed state fails. A callback from a browser that did not start the flow fails.
- A changed `return_to`, OP endpoint, claimed ID, identity, nonce, signature, or required signed-field list fails.
- Direct verification sends only OpenID fields and accepts only an exact, successful `is_valid:true` response.
- Steam's HTTPS claimed ID succeeds. The HTTP form, invalid hosts, invalid paths, and nonnumeric IDs fail.
- Synthetic and mapped emails remain unverified. A same-email collision does not link a Steam account implicitly. Explicit linking requires an existing authenticated session.
- Relative and configured trusted-origin redirects succeed. Untrusted normal, error, and configured fallback URLs fail. Query strings and fragments remain valid.
- `image: undefined` uses the Steam avatar. `image: null` removes the image.
- Schema model and field renames work. Arbitrary schema definitions fail type checking.
- Every public error code has a test that emits the code. No path emits an undeclared plugin code.
- Sign-in and callback rate limits work. OpenID verification times out and fails closed. A profile timeout uses the documented fallback.
- The session cookie cache contains the final user, including `steamId`.

## Optimization opportunity

The plugin can skip the player-summary request for an existing Steam account when the plugin does not update user information on sign-in. This change reduces callback latency and Steam API use. Keep this optimization separate from the security and conformance changes unless profile refresh is part of the public contract.
