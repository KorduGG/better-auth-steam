import { defineErrorCodes } from 'better-auth';

export const STEAM_ERROR_CODES = defineErrorCodes({
	STEAM_VERIFICATION_FAILED: 'Steam OpenID verification failed.',
	STEAM_ACCOUNT_NOT_LINKED: 'No user linked this Steam account.',
	STEAM_UNABLE_TO_LINK_ACCOUNT: 'The plugin cannot link the Steam account.',
	STEAM_ACCOUNT_LINKING_DISABLED: 'The application does not allow Steam account linking.',
	STEAM_DIFFERENT_EMAIL_LINKING_DISABLED:
		'The plugin cannot link accounts with different email addresses.',
	STEAM_ACCOUNT_ALREADY_LINKED: 'A different user already linked this Steam account.',
	STEAM_UNABLE_TO_CREATE_USER: 'The plugin cannot create a user from the Steam profile.',
	STEAM_UNABLE_TO_CREATE_SESSION: 'The plugin cannot create a Steam session.',
	STEAM_AUTHENTICATION_FAILED: 'Steam authentication failed.'
});
