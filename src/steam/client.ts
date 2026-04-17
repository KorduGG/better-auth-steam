import type { BetterAuthClientPlugin } from 'better-auth/client';
import type { steamOpenID } from './index';

export const steamOpenIDClient = () => {
	return {
		id: 'steam-openid',
		$InferServerPlugin: {} as ReturnType<typeof steamOpenID>
	} satisfies BetterAuthClientPlugin;
};
