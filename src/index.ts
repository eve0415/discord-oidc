import { SignJWT } from "jose";

export interface Env {
  DISCORD_CLIENT_ID: string;
  DISCORD_CLIENT_SECRET: string;
  KV: KVNamespace;
}

const scope = "identify email guilds" as const;
const algorithm = {
  name: "RSASSA-PKCS1-v1_5",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
} as const;

export default <ExportedHandler<Env>>{
  async fetch(request, env, context) {
    const requestURL = new URL(request.url);

    if (request.method === "POST" && requestURL.pathname === "/callback") {
      const data = await request.formData();

      const formdata = new URLSearchParams({
        client_id: env.DISCORD_CLIENT_ID,
        client_secret: env.DISCORD_CLIENT_SECRET,
        code_verifier: data.get("code_verifier") ?? "",
        redirect_uri: data.get("redirect_uri") ?? "",
        code: data.get("code") ?? "",
        grant_type: data.get("grant_type") ?? "",
        scope: scope,
      });

      const auth = await fetch("https://discord.com/api/v10/oauth2/token", {
        method: "POST",
        body: formdata.toString(),
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }).then((res) =>
        res.json<{
          token_type: "Bearer";
          access_token: string;
          expires_in: number;
          refresh_token: string;
          scope: typeof scope;
        }>(),
      );

      const user = await fetch("https://discord.com/api/v10/users/@me", {
        headers: {
          Authorization: `${auth.token_type} ${auth.access_token}`,
        },
      }).then((res) =>
        res.json<{
          id: string;
          username: string;
          discriminator: string;
          global_name?: string;
          email: string;
          verified: boolean;
        }>(),
      );
      if (!user.verified) {
        return Response.json(
          { message: "Please verify your email." },
          { status: 403, statusText: "Forbidden" },
        );
      }

      const privateKey = await (async () => {
        const cachedRawKey = await env.KV.get<JsonWebKey>("privateKey", "json");
        if (cachedRawKey) {
          return await crypto.subtle.importKey(
            "jwk",
            cachedRawKey,
            algorithm,
            true,
            ["sign"],
          );
        }

        const keyPair = (await crypto.subtle.generateKey(algorithm, true, [
          "sign",
          "verify",
        ])) as CryptoKeyPair;
        const publicKey = await crypto.subtle.exportKey(
          "jwk",
          keyPair.publicKey,
        );
        const privateKey = await crypto.subtle.exportKey(
          "jwk",
          keyPair.privateKey,
        );
        context.waitUntil(
          env.KV.put("publicKey", JSON.stringify(publicKey), {
            expirationTtl: 60 * 60,
          }),
        );
        context.waitUntil(
          env.KV.put("privateKey", JSON.stringify(privateKey), {
            expirationTtl: 60 * 60,
          }),
        );

        return keyPair.privateKey;
      })();

      const token: { [key: string]: string | string[] } = {
        email: user.email,
        id: user.id,
        // name:
        //   user.global_name ??
        //   `${user.username}${
        //     user.discriminator === "0" ? "" : `#${user.discriminator}`
        //   }`,
      };

      const guildsResponse = await fetch(
        "https://discord.com/api/v10/users/@me/guilds",
        {
          headers: {
            Authorization: `${auth.token_type} ${auth.access_token}`,
          },
        },
      );
      if (guildsResponse.status === 200) {
        const guilds = await guildsResponse.json<
          {
            id: string;
            name: string;
            owner: boolean;
            permissions: string;
          }[]
        >();
        token.guilds = guilds.map(({ id }) => id);
      }

      return Response.json({
        id_token: await new SignJWT(token)
          .setIssuer(requestURL.origin)
          .setAudience(env.DISCORD_CLIENT_ID)
          .setSubject(user.id)
          .setProtectedHeader({ alg: "RS256", kid: "jwtRS256" })
          .setExpirationTime("1h")
          .sign(privateKey),
      });
    }

    if (request.method !== "GET") {
      return new Response(null, {
        status: 405,
        statusText: "Method Not Allowed",
      });
    }

    if (requestURL.pathname === "/authorize") {
      const auth = new URL("https://discord.com/oauth2/authorize");
      auth.searchParams.set(
        "client_id",
        requestURL.searchParams.get("client_id") ?? "",
      );
      auth.searchParams.set("scope", scope);
      auth.searchParams.set(
        "state",
        requestURL.searchParams.get("state") ?? "",
      );
      auth.searchParams.set(
        "code_challenge",
        requestURL.searchParams.get("code_challenge") ?? "",
      );
      auth.searchParams.set("code_challenge_method", "S256");
      auth.searchParams.set(
        "redirect_uri",
        requestURL.searchParams.get("redirect_uri") ?? "",
      );
      auth.searchParams.set("response_type", "code");

      return Response.redirect(auth.toString());
    }

    if (requestURL.pathname === "/certificate") {
      const publicKey = await env.KV.get<JsonWebKey>("publicKey", "json");
      if (!publicKey) {
        return new Response(null, {
          status: 404,
          statusText: "Not Found",
        });
      }

      return Response.json({
        keys: [
          {
            alg: "RS256",
            kid: "jwtRS256",
            ...(await crypto.subtle.exportKey(
              "jwk",
              await crypto.subtle.importKey("jwk", publicKey, algorithm, true, [
                "verify",
              ]),
            )),
          },
        ],
      });
    }

    return new Response(null, {
      status: 404,
      statusText: "Not Found",
    });
  },
};
