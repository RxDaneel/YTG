/*
  YTG – server di rinnovo dell'accesso Google (Cloudflare Worker)

  Custodisce il "client secret" di Google e lo usa per:
    POST /exchange  { code }           → primo accesso: restituisce access_token + refresh_token
    POST /refresh   { refresh_token }  → rinnovo: restituisce un nuovo access_token (valido 1 ora)

  Variabili da impostare in Cloudflare (Settings → Variables and Secrets):
    CLIENT_ID       testo   l'ID client di YTG (finisce con .apps.googleusercontent.com)
    CLIENT_SECRET   SEGRETO il client secret di Google (tipo "Secret", mai "Text")
    REDIRECT_URI    testo   https://rxdaneel.github.io/YTG/
    ALLOWED_ORIGIN  testo   https://rxdaneel.github.io
*/
export default {
  async fetch(req, env) {
    const allowed = env.ALLOWED_ORIGIN || "https://rxdaneel.github.io";
    const cors = {
      "Access-Control-Allow-Origin": allowed,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin",
    };
    const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { ...cors, "Content-Type": "application/json" } });

    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (req.method === "GET") return json({ ok: true, app: "YTG auth", configured: !!(env.CLIENT_ID && env.CLIENT_SECRET && env.REDIRECT_URI) });
    if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);
    if ((req.headers.get("Origin") || "") !== allowed) return json({ error: "origin_not_allowed" }, 403);   // solo YTG può usarlo
    if (!env.CLIENT_ID || !env.CLIENT_SECRET || !env.REDIRECT_URI) return json({ error: "server_not_configured", error_description: "Mancano CLIENT_ID, CLIENT_SECRET o REDIRECT_URI" }, 500);

    let body;
    try { body = await req.json(); } catch { return json({ error: "bad_request" }, 400); }

    const path = new URL(req.url).pathname.replace(/\/+$/, "");
    const p = new URLSearchParams({ client_id: env.CLIENT_ID, client_secret: env.CLIENT_SECRET });
    if (path === "/exchange") {
      if (!body.code) return json({ error: "missing_code" }, 400);
      p.set("grant_type", "authorization_code"); p.set("code", body.code); p.set("redirect_uri", env.REDIRECT_URI);
    } else if (path === "/refresh") {
      if (!body.refresh_token) return json({ error: "missing_refresh_token" }, 400);
      p.set("grant_type", "refresh_token"); p.set("refresh_token", body.refresh_token);
    } else return json({ error: "not_found" }, 404);

    const r = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: p,
    });
    const j = await r.json().catch(() => ({}));
    // al browser torna solo quello che serve: il client secret non esce mai da qui
    return json({
      access_token: j.access_token, expires_in: j.expires_in, scope: j.scope,
      refresh_token: j.refresh_token, error: j.error, error_description: j.error_description,
    }, r.status);
  },
};
