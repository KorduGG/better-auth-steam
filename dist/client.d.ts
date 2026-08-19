import { s as steamOpenID } from './index-DgR7k534.js';
import 'better-auth';
import 'zod';

declare const steamOpenIDClient: () => {
    id: "steam-openid";
    $InferServerPlugin: ReturnType<typeof steamOpenID>;
    pathMethods: {
        '/steam/login': "POST";
        '/steam/link': "POST";
    };
};

export { steamOpenIDClient };
