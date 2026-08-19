// src/steam/client.ts
var steamOpenIDClient = () => {
  return {
    id: "steam-openid",
    $InferServerPlugin: {},
    pathMethods: {
      "/steam/login": "POST",
      "/steam/link": "POST"
    }
  };
};
export {
  steamOpenIDClient
};
//# sourceMappingURL=client.js.map