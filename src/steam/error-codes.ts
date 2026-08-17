import { defineErrorCodes } from 'better-auth';

export const STEAM_ERROR_CODES = defineErrorCodes({
	STEAM_VERIFICATION_FAILED: 'Steam OpenID verification failed.',
	STEAM_ACCOUNT_NOT_LINKED: 'The Steam account was not linked.',
	STEAM_UNABLE_TO_LINK_ACCOUNT: 'The plugin cannot link the Steam account.',
	STEAM_ACCOUNT_LINKING_DISABLED: 'Steam account linking is disabled.',
	STEAM_DIFFERENT_EMAIL_LINKING_DISABLED:
		'The plugin cannot link accounts with different email addresses.',
	STEAM_ACCOUNT_ALREADY_LINKED: 'The Steam account is linked to another user.',
	STEAM_UNABLE_TO_CREATE_USER: 'The plugin cannot create a user from the Steam profile.',
	STEAM_UNABLE_TO_CREATE_SESSION: 'The plugin cannot create a Steam session.',
	STEAM_AUTHENTICATION_FAILED: 'Steam authentication failed.'
});
