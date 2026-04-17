export const STEAM_ERROR_CODES = {
	STEAM_VERIFICATION_FAILED: 'Steam OpenID verification failed',
	INVALID_STEAM_CLAIMED_ID: 'Invalid Steam OpenID claimed_id',
	STEAM_API_UNAVAILABLE: 'Steam Web API is unavailable',
	UNABLE_TO_CREATE_USER: 'Unable to create user from Steam profile',
	UNABLE_TO_LINK_ACCOUNT: 'Unable to link Steam account'
} as const;
