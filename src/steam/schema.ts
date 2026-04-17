import type { BetterAuthPluginDBSchema } from 'better-auth/db';

export const schema = {
	user: {
		fields: {
			steamId: {
				type: 'string',
				required: false,
				unique: true,
				input: false,
				returned: true
			}
		}
	}
} satisfies BetterAuthPluginDBSchema;
