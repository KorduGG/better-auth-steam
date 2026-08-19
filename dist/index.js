// src/steam/index.ts
import { HIDE_METADATA } from "better-auth";
import { APIError, createAuthEndpoint, sessionMiddleware } from "better-auth/api";
import { generateState, handleOAuthUserInfo, parseState } from "better-auth/oauth2";
import { setSessionCookie } from "better-auth/cookies";
import { createOAuthAccountIssuer, mergeSchema } from "better-auth/db";
import * as z from "zod";

// src/steam/openid.ts
var STEAM_OPENID_URL = "https://steamcommunity.com/openid/login";
var OPENID_NAMESPACE = "http://specs.openid.net/auth/2.0";
var STEAM_ID_REGEX = /^https:\/\/steamcommunity\.com\/openid\/id\/(\d+)$/;
var REQUIRED_SIGNED_FIELDS = [
  "op_endpoint",
  "claimed_id",
  "identity",
  "return_to",
  "response_nonce",
  "assoc_handle"
];
var STEAM_REQUEST_TIMEOUT_MS = 1e4;
var RESPONSE_NONCE_MAX_LENGTH = 255;
var RESPONSE_NONCE_MAX_AGE_MS = 10 * 60 * 1e3;
function parseResponseNonce(value) {
  if (value.length > RESPONSE_NONCE_MAX_LENGTH) {
    return void 0;
  }
  const match = value.match(
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z[\x21-\x7e]*$/
  );
  if (!match) {
    return void 0;
  }
  const [, year, month, day, hour, minute, second] = match;
  const timestamp = Date.UTC(
    Number(year),
    Number(month) - 1,
    Number(day),
    Number(hour),
    Number(minute),
    Number(second)
  );
  const date = new Date(timestamp);
  if (date.getUTCFullYear() !== Number(year) || date.getUTCMonth() !== Number(month) - 1 || date.getUTCDate() !== Number(day) || date.getUTCHours() !== Number(hour) || date.getUTCMinutes() !== Number(minute) || date.getUTCSeconds() !== Number(second)) {
    return void 0;
  }
  return timestamp;
}
function parseDirectVerificationResponse(text) {
  const fields = /* @__PURE__ */ new Map();
  for (const line of text.split(/\r?\n/)) {
    if (!line) {
      continue;
    }
    const separator = line.indexOf(":");
    if (separator < 1) {
      throw new Error("Invalid Steam OpenID verification response");
    }
    const key = line.slice(0, separator);
    if (fields.has(key)) {
      throw new Error(`Duplicate Steam OpenID verification field: ${key}`);
    }
    fields.set(key, line.slice(separator + 1));
  }
  return fields;
}
function buildSteamOpenIDRedirectURL(realm, returnTo) {
  const params = new URLSearchParams({
    "openid.ns": "http://specs.openid.net/auth/2.0",
    "openid.mode": "checkid_setup",
    "openid.return_to": returnTo,
    "openid.realm": realm,
    "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
    "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select"
  });
  return `${STEAM_OPENID_URL}?${params.toString()}`;
}
async function verifySteamOpenIDResponse(params, expectedReturnTo) {
  const fieldNames = /* @__PURE__ */ new Set();
  for (const [name] of params) {
    if (name.startsWith("openid.") && fieldNames.has(name)) {
      throw new Error(`Duplicate OpenID field: ${name}`);
    }
    fieldNames.add(name);
  }
  if (params.get("openid.ns") !== OPENID_NAMESPACE) {
    throw new Error("Invalid openid.ns");
  }
  if (params.get("openid.mode") !== "id_res") {
    throw new Error("Invalid openid.mode");
  }
  if (params.get("openid.op_endpoint") !== STEAM_OPENID_URL) {
    throw new Error("Invalid openid.op_endpoint");
  }
  if (params.get("openid.return_to") !== expectedReturnTo) {
    throw new Error("Invalid openid.return_to");
  }
  const claimedId = params.get("openid.claimed_id");
  if (!claimedId) {
    throw new Error("Missing openid.claimed_id");
  }
  const match = claimedId.match(STEAM_ID_REGEX);
  if (!match) {
    throw new Error("Invalid openid.claimed_id format");
  }
  if (params.get("openid.identity") !== claimedId) {
    throw new Error("Invalid openid.identity");
  }
  for (const name of ["openid.assoc_handle", "openid.signed", "openid.sig"]) {
    if (!params.get(name)) {
      throw new Error(`Missing ${name}`);
    }
  }
  const associationHandle = params.get("openid.assoc_handle");
  if (associationHandle.length > 255 || !/^[\x21-\x7e]+$/.test(associationHandle)) {
    throw new Error("Invalid openid.assoc_handle");
  }
  const signature = params.get("openid.sig");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
    signature
  )) {
    throw new Error("Invalid openid.sig");
  }
  const responseNonce = params.get("openid.response_nonce");
  if (!responseNonce) {
    throw new Error("Missing openid.response_nonce");
  }
  const nonceTimestamp = parseResponseNonce(responseNonce);
  if (nonceTimestamp === void 0 || Math.abs(Date.now() - nonceTimestamp) > RESPONSE_NONCE_MAX_AGE_MS) {
    throw new Error("Invalid openid.response_nonce");
  }
  const signedFieldList = params.get("openid.signed").split(",");
  const signedFields = new Set(signedFieldList);
  if (signedFields.size !== signedFieldList.length || signedFieldList.some((field) => !/^[A-Za-z0-9_.-]+$/.test(field))) {
    throw new Error("Invalid openid.signed");
  }
  for (const field of REQUIRED_SIGNED_FIELDS) {
    if (!signedFields.has(field)) {
      throw new Error(`Missing signed OpenID field: ${field}`);
    }
  }
  const verifyParams = new URLSearchParams();
  for (const [key, value] of params.entries()) {
    if (key.startsWith("openid.")) {
      verifyParams.set(key, value);
    }
  }
  verifyParams.set("openid.mode", "check_authentication");
  const response = await fetch(STEAM_OPENID_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: verifyParams.toString(),
    redirect: "manual",
    signal: AbortSignal.timeout(STEAM_REQUEST_TIMEOUT_MS)
  });
  if (response.status !== 200) {
    throw new Error(`Steam OpenID error: ${response.status}`);
  }
  const fields = parseDirectVerificationResponse(await response.text());
  if (fields.get("ns") !== OPENID_NAMESPACE || fields.get("is_valid") !== "true") {
    throw new Error("Steam OpenID verification failed");
  }
  return {
    responseNonce,
    responseNonceExpiresAt: new Date(
      nonceTimestamp + RESPONSE_NONCE_MAX_AGE_MS
    ),
    steamId: match[1]
  };
}
async function fetchSteamPlayerSummary(steamId, apiKey) {
  const url = `https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=${encodeURIComponent(apiKey)}&steamids=${encodeURIComponent(steamId)}`;
  const response = await fetch(url, {
    redirect: "manual",
    signal: AbortSignal.timeout(STEAM_REQUEST_TIMEOUT_MS)
  });
  if (!response.ok) {
    throw new Error(`Steam API error: ${response.status}`);
  }
  const data = await response.json();
  const player = data?.response?.players?.[0];
  if (!player || typeof player !== "object") {
    throw new Error("Player not found in Steam API response");
  }
  const candidate = player;
  if (candidate.steamid !== steamId) {
    throw new Error("Steam profile identity mismatch");
  }
  if (typeof candidate.personaname !== "string" || !candidate.personaname || typeof candidate.avatarfull !== "string" || typeof candidate.profileurl !== "string") {
    throw new Error("Invalid Steam profile response");
  }
  return candidate;
}

// src/steam/schema.ts
var schema = {
  user: {
    fields: {
      steamId: {
        type: "string",
        required: false,
        unique: true,
        input: false,
        returned: true
      }
    }
  }
};

// src/steam/error-codes.ts
import { defineErrorCodes } from "better-auth";
var STEAM_ERROR_CODES = defineErrorCodes({
  STEAM_VERIFICATION_FAILED: "Steam OpenID verification failed.",
  STEAM_ACCOUNT_NOT_LINKED: "No user linked this Steam account.",
  STEAM_UNABLE_TO_LINK_ACCOUNT: "The plugin cannot link the Steam account.",
  STEAM_ACCOUNT_LINKING_DISABLED: "The application does not allow Steam account linking.",
  STEAM_DIFFERENT_EMAIL_LINKING_DISABLED: "The plugin cannot link accounts with different email addresses.",
  STEAM_ACCOUNT_ALREADY_LINKED: "A different user already linked this Steam account.",
  STEAM_UNABLE_TO_CREATE_USER: "The plugin cannot create a user from the Steam profile.",
  STEAM_UNABLE_TO_CREATE_SESSION: "The plugin cannot create a Steam session.",
  STEAM_AUTHENTICATION_FAILED: "Steam authentication failed."
});

// src/steam/redirect.ts
function normalizeRedirectTarget(input, baseURL, fallback, isTrustedOrigin) {
  const isAllowed = (target) => isTrustedOrigin(target, { allowRelativePaths: true });
  if (input && isAllowed(input)) {
    return input;
  }
  if (isAllowed(fallback)) {
    return fallback;
  }
  return `${baseURL}/error`;
}
function addErrorToRedirect(target, code, baseURL) {
  const url = new URL(target, baseURL);
  url.searchParams.set("error", code);
  if (target.startsWith("/")) {
    return `${url.pathname}${url.search}${url.hash}`;
  }
  return url.toString();
}

// src/steam/index.ts
var PROVIDER_ID = "steam";
var PROVIDER_ISSUER = createOAuthAccountIssuer(PROVIDER_ID);
var OAUTH_ERROR_CODES = {
  "account not linked": "STEAM_ACCOUNT_NOT_LINKED",
  "unable to link account": "STEAM_UNABLE_TO_LINK_ACCOUNT",
  "unable to create user": "STEAM_UNABLE_TO_CREATE_USER",
  "unable to create session": "STEAM_UNABLE_TO_CREATE_SESSION"
};
var STATE_ERROR_CODES = /* @__PURE__ */ new Set([
  "internal_server_error",
  "state_generation_error",
  "state_invalid",
  "state_mismatch",
  "state_not_found"
]);
var steamRateLimit = {
  pathMatcher: (path) => path.startsWith("/steam/"),
  window: 60,
  max: 10
};
function prepareSteamFlow(body, baseURL, isTrustedOrigin) {
  body.callbackURL = normalizeRedirectTarget(
    body.callbackURL,
    baseURL,
    "/",
    isTrustedOrigin
  );
  body.errorCallbackURL = normalizeRedirectTarget(
    body.errorCallbackURL,
    baseURL,
    `${baseURL}/error`,
    isTrustedOrigin
  );
  return {
    callbackEndpoint: `${baseURL}/steam/callback`,
    realm: new URL(baseURL).origin
  };
}
function buildSteamAuthorizationURL(callbackEndpoint, realm, state) {
  const returnTo = new URL(callbackEndpoint);
  returnTo.searchParams.set("state", state);
  return buildSteamOpenIDRedirectURL(realm, returnTo.toString());
}
async function createNonceIdentifier(responseNonce) {
  const data = new TextEncoder().encode(
    `https://steamcommunity.com/openid/login:${responseNonce}`
  );
  const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
  const hash = Array.from(
    new Uint8Array(digest),
    (byte) => byte.toString(16).padStart(2, "0")
  ).join("");
  return `steam-openid:${hash}`;
}
var steamOpenID = (options) => {
  const emailDomain = options.syntheticEmailDomain ?? "steam.invalid";
  return {
    id: "steam-openid",
    schema: mergeSchema(schema, options.schema),
    endpoints: {
      signInWithSteam: createAuthEndpoint(
        "/steam/login",
        {
          method: "POST",
          body: z.object({
            callbackURL: z.string().optional(),
            errorCallbackURL: z.string().optional()
          }),
          requireHeaders: true,
          requireRequest: true,
          metadata: {
            openapi: {
              description: "Redirect the user to Steam for OpenID authentication",
              responses: {
                "200": { description: "The response contains the Steam OpenID login URL." }
              }
            }
          }
        },
        async (ctx) => {
          const isTrustedRedirect = (url2, settings) => ctx.context.isTrustedOrigin(url2, settings);
          const { callbackEndpoint, realm } = prepareSteamFlow(
            ctx.body,
            ctx.context.baseURL,
            isTrustedRedirect
          );
          const { state } = await generateState(ctx, {
            additionalData: { returnTo: callbackEndpoint }
          });
          const url = buildSteamAuthorizationURL(callbackEndpoint, realm, state);
          ctx.setHeader("Location", url);
          return ctx.json({
            url,
            redirect: true
          });
        }
      ),
      linkSteamAccount: createAuthEndpoint(
        "/steam/link",
        {
          method: "POST",
          body: z.object({
            callbackURL: z.string().optional(),
            errorCallbackURL: z.string().optional()
          }),
          requireHeaders: true,
          requireRequest: true,
          use: [sessionMiddleware],
          metadata: {
            openapi: {
              description: "Link Steam to the authenticated user",
              responses: {
                "200": { description: "The response contains the Steam account-link URL." }
              }
            }
          }
        },
        async (ctx) => {
          const linking = ctx.context.options.account?.accountLinking;
          if (linking?.enabled === false) {
            throw APIError.from(
              "BAD_REQUEST",
              STEAM_ERROR_CODES.STEAM_ACCOUNT_LINKING_DISABLED
            );
          }
          if (linking?.allowDifferentEmails !== true) {
            throw APIError.from(
              "BAD_REQUEST",
              STEAM_ERROR_CODES.STEAM_DIFFERENT_EMAIL_LINKING_DISABLED
            );
          }
          const isTrustedRedirect = (url2, settings) => ctx.context.isTrustedOrigin(url2, settings);
          const { callbackEndpoint, realm } = prepareSteamFlow(
            ctx.body,
            ctx.context.baseURL,
            isTrustedRedirect
          );
          const { state } = await generateState(
            ctx,
            {
              link: {
                email: ctx.context.session.user.email,
                userId: ctx.context.session.user.id
              },
              additionalData: { returnTo: callbackEndpoint }
            }
          );
          const url = buildSteamAuthorizationURL(callbackEndpoint, realm, state);
          ctx.setHeader("Location", url);
          return ctx.json({
            url,
            redirect: true
          });
        }
      ),
      steamCallback: createAuthEndpoint(
        "/steam/callback",
        {
          method: "GET",
          query: z.object({ state: z.string() }),
          requireRequest: true,
          metadata: {
            ...HIDE_METADATA,
            openapi: {
              description: "Steam OpenID callback",
              responses: {
                "302": { description: "The endpoint redirects to the original callback URL." }
              }
            }
          }
        },
        async (ctx) => {
          const isTrustedRedirect = (url, settings) => ctx.context.isTrustedOrigin(url, settings);
          const defaultErrorURL = normalizeRedirectTarget(
            ctx.context.options.onAPIError?.errorURL,
            ctx.context.baseURL,
            `${ctx.context.baseURL}/error`,
            isTrustedRedirect
          );
          const redirectWithError = (target, code) => {
            throw ctx.redirect(addErrorToRedirect(target, code, ctx.context.baseURL));
          };
          let stateData;
          try {
            stateData = await parseState(ctx);
          } catch (error) {
            let code = "state_mismatch";
            let target = defaultErrorURL;
            if (error && typeof error === "object" && "headers" in error) {
              const headers = error.headers;
              const location = headers ? new Headers(headers).get("location") : null;
              let stateErrorMatch;
              for (const match of location?.matchAll(/[?&]error=([^&#]+)/g) ?? []) {
                let parsedCode;
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
            "/",
            isTrustedRedirect
          );
          const returnTo = new URL(String(stateData.returnTo));
          returnTo.searchParams.set("state", ctx.query.state);
          let steamId;
          try {
            const params = new URL(ctx.request.url).searchParams;
            const verification = await verifySteamOpenIDResponse(
              params,
              returnTo.toString()
            );
            steamId = verification.steamId;
            const nonceIdentifier = await createNonceIdentifier(
              verification.responseNonce
            );
            const existingNonce = await ctx.context.internalAdapter.findVerificationValue(
              nonceIdentifier
            );
            const reserved = !existingNonce && await ctx.context.internalAdapter.reserveVerificationValue({
              identifier: nonceIdentifier,
              value: steamId,
              expiresAt: verification.responseNonceExpiresAt
            });
            if (!reserved) {
              throw new Error(
                "The plugin detected a repeated Steam OpenID response nonce."
              );
            }
          } catch (e) {
            ctx.context.logger.error("Steam OpenID verification failed.", e);
            return redirectWithError(errorRedirectBase, "STEAM_VERIFICATION_FAILED");
          }
          let defaultName = `Steam User ${steamId}`;
          let defaultImage;
          let profile;
          try {
            profile = await fetchSteamPlayerSummary(steamId, options.apiKey);
            defaultName = profile.personaname;
            defaultImage = profile.avatarfull;
          } catch (e) {
            ctx.context.logger.warn(
              "Steam Web API is unavailable. The plugin uses the default profile.",
              e
            );
          }
          const profileOverrides = profile ? options.mapProfileToUser?.(profile) : void 0;
          const name = profileOverrides?.name ?? defaultName;
          const image = profileOverrides?.image === void 0 ? defaultImage : profileOverrides.image;
          const email = profileOverrides?.email ?? `steam_${steamId}@${emailDomain}`;
          const link = stateData.link;
          if (link) {
            const linking = ctx.context.options.account?.accountLinking;
            if (linking?.enabled === false) {
              return redirectWithError(
                errorRedirectBase,
                "STEAM_ACCOUNT_LINKING_DISABLED"
              );
            }
            if (linking?.allowDifferentEmails !== true) {
              return redirectWithError(
                errorRedirectBase,
                "STEAM_DIFFERENT_EMAIL_LINKING_DISABLED"
              );
            }
            let existingAccount;
            try {
              existingAccount = await ctx.context.internalAdapter.findAccountByKey({
                issuer: PROVIDER_ISSUER,
                accountId: steamId
              });
            } catch (error) {
              ctx.context.logger.error(
                "The plugin could not check the Steam account owner.",
                error
              );
              return redirectWithError(
                errorRedirectBase,
                "STEAM_UNABLE_TO_LINK_ACCOUNT"
              );
            }
            if (existingAccount && existingAccount.userId.toString() !== link.userId) {
              return redirectWithError(errorRedirectBase, "STEAM_ACCOUNT_ALREADY_LINKED");
            }
            let createdAccount;
            try {
              if (!existingAccount) {
                createdAccount = await ctx.context.internalAdapter.createAccount({
                  userId: link.userId,
                  providerId: PROVIDER_ID,
                  issuer: PROVIDER_ISSUER,
                  accountId: steamId
                });
                if (!createdAccount) {
                  return redirectWithError(
                    errorRedirectBase,
                    "STEAM_UNABLE_TO_LINK_ACCOUNT"
                  );
                }
              }
              const updatedUser = await ctx.context.internalAdapter.updateUser(
                link.userId,
                { steamId }
              );
              if (!updatedUser) {
                throw new Error("The user update did not complete.");
              }
            } catch (error) {
              ctx.context.logger.error("Steam account linking failed.", error);
              if (createdAccount) {
                await ctx.context.internalAdapter.deleteAccount(createdAccount.id).catch((cleanupError) => {
                  ctx.context.logger.error(
                    "The plugin could not remove a partial Steam account link.",
                    cleanupError
                  );
                });
              }
              return redirectWithError(
                errorRedirectBase,
                "STEAM_UNABLE_TO_LINK_ACCOUNT"
              );
            }
            throw ctx.redirect(callbackURL);
          }
          let result;
          try {
            result = await handleOAuthUserInfo(ctx, {
              userInfo: {
                id: steamId,
                email,
                name,
                image,
                emailVerified: false,
                steamId
              },
              account: {
                providerId: PROVIDER_ID,
                issuer: PROVIDER_ISSUER,
                accountId: steamId
              },
              callbackURL,
              overrideUserInfo: options.overrideUserInfoOnSignIn,
              trustProviderByName: false
            });
          } catch (error) {
            ctx.context.logger.error("Steam authentication failed.", error);
            return redirectWithError(
              errorRedirectBase,
              "STEAM_AUTHENTICATION_FAILED"
            );
          }
          if (result.error !== null) {
            ctx.context.logger.error("Steam login failed.", { error: result.error });
            return redirectWithError(
              errorRedirectBase,
              OAUTH_ERROR_CODES[result.error] ?? "STEAM_AUTHENTICATION_FAILED"
            );
          }
          let authenticatedUser = result.data.user;
          if (authenticatedUser.steamId !== steamId) {
            try {
              const updatedUser = await ctx.context.internalAdapter.updateUser(
                authenticatedUser.id,
                { steamId }
              );
              if (!updatedUser) {
                throw new Error("The user update did not complete.");
              }
              authenticatedUser = updatedUser;
            } catch (error) {
              ctx.context.logger.error(
                "The plugin could not store the Steam ID on the user.",
                error
              );
              return redirectWithError(
                errorRedirectBase,
                "STEAM_AUTHENTICATION_FAILED"
              );
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
  };
};
export {
  STEAM_ERROR_CODES,
  steamOpenID
};
//# sourceMappingURL=index.js.map