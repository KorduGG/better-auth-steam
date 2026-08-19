import * as better_auth from 'better-auth';
import { InferOptionSchema } from 'better-auth';
import * as z from 'zod';

interface SteamPlayerSummary {
    steamid: string;
    personaname: string;
    avatarfull: string;
    profileurl: string;
    [key: string]: unknown;
}

declare const schema: {
    user: {
        fields: {
            steamId: {
                type: "string";
                required: false;
                unique: true;
                input: false;
                returned: true;
            };
        };
    };
};

interface SteamPluginOptions {
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
declare const steamOpenID: (options: SteamPluginOptions) => {
    id: "steam-openid";
    schema: {
        user: {
            fields: {
                steamId: {
                    type: "string";
                    required: false;
                    unique: true;
                    input: false;
                    returned: true;
                };
            };
        };
    };
    endpoints: {
        signInWithSteam: better_auth.StrictEndpoint<"/steam/login", {
            method: "POST";
            body: z.ZodObject<{
                callbackURL: z.ZodOptional<z.ZodString>;
                errorCallbackURL: z.ZodOptional<z.ZodString>;
            }, z.core.$strip>;
            requireHeaders: true;
            requireRequest: true;
            metadata: {
                openapi: {
                    description: string;
                    responses: {
                        '200': {
                            description: string;
                        };
                    };
                };
            };
        }, {
            url: string;
            redirect: boolean;
        }>;
        linkSteamAccount: better_auth.StrictEndpoint<"/steam/link", {
            method: "POST";
            body: z.ZodObject<{
                callbackURL: z.ZodOptional<z.ZodString>;
                errorCallbackURL: z.ZodOptional<z.ZodString>;
            }, z.core.$strip>;
            requireHeaders: true;
            requireRequest: true;
            use: better_auth.Middleware<better_auth.MiddlewareOptions, (inputContext: better_auth.MiddlewareInputContext<better_auth.MiddlewareOptions>) => Promise<{
                session: {
                    session: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        userId: string;
                        expiresAt: Date;
                        token: string;
                        ipAddress?: string | null | undefined;
                        userAgent?: string | null | undefined;
                    };
                    user: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        email: string;
                        emailVerified: boolean;
                        name: string;
                        image?: string | null | undefined;
                    };
                };
            }>>[];
            metadata: {
                openapi: {
                    description: string;
                    responses: {
                        '200': {
                            description: string;
                        };
                    };
                };
            };
        }, {
            url: string;
            redirect: boolean;
        }>;
        steamCallback: better_auth.StrictEndpoint<"/steam/callback", {
            method: "GET";
            query: z.ZodObject<{
                state: z.ZodString;
            }, z.core.$strip>;
            requireRequest: true;
            metadata: {
                openapi: {
                    description: string;
                    responses: {
                        '302': {
                            description: string;
                        };
                    };
                };
                scope: "server";
            };
        }, never>;
    };
    rateLimit: {
        pathMatcher: (path: string) => boolean;
        window: number;
        max: number;
    }[];
    options: SteamPluginOptions;
    $ERROR_CODES: {
        STEAM_VERIFICATION_FAILED: better_auth.RawError<"STEAM_VERIFICATION_FAILED">;
        STEAM_ACCOUNT_NOT_LINKED: better_auth.RawError<"STEAM_ACCOUNT_NOT_LINKED">;
        STEAM_UNABLE_TO_LINK_ACCOUNT: better_auth.RawError<"STEAM_UNABLE_TO_LINK_ACCOUNT">;
        STEAM_ACCOUNT_LINKING_DISABLED: better_auth.RawError<"STEAM_ACCOUNT_LINKING_DISABLED">;
        STEAM_DIFFERENT_EMAIL_LINKING_DISABLED: better_auth.RawError<"STEAM_DIFFERENT_EMAIL_LINKING_DISABLED">;
        STEAM_ACCOUNT_ALREADY_LINKED: better_auth.RawError<"STEAM_ACCOUNT_ALREADY_LINKED">;
        STEAM_UNABLE_TO_CREATE_USER: better_auth.RawError<"STEAM_UNABLE_TO_CREATE_USER">;
        STEAM_UNABLE_TO_CREATE_SESSION: better_auth.RawError<"STEAM_UNABLE_TO_CREATE_SESSION">;
        STEAM_AUTHENTICATION_FAILED: better_auth.RawError<"STEAM_AUTHENTICATION_FAILED">;
    };
};

export { type SteamPlayerSummary as S, type SteamPluginOptions as a, steamOpenID as s };
