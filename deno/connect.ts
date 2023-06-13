import * as nats from "https://deno.land/x/nats@v1.13.0/src/mod.ts";

export async function connectFromEnv(extraOpts: nats.ConnectionOptions = {}): Promise<nats.ConnectionOptions> {
    return {
        servers: Deno.env.get("NATS_URL"),
        authenticator: nats.credsAuthenticator(
            new TextEncoder().encode(await Deno.readTextFile(Deno.env.get("NATS_CREDS_FILE") || "./auth.creds"))
        ),
        inboxPrefix: Deno.env.get("NATS_INBOX_PREFIX"),
        ...extraOpts
    };
}
