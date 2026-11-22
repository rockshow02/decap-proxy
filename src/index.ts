import { OAuthClient } from "./oauth";

interface Env {
  GITHUB_OAUTH_ID: string;
  GITHUB_OAUTH_SECRET: string;
  GITHUB_REPO_PRIVATE?: string;
  ALLOWED_ORIGINS?: string;
}

const STATE_COOKIE = "oauth_state";
const COOKIE_ATTRS = "Path=/; HttpOnly; Secure; SameSite=Lax";

export const parseAllowedOrigins = (value?: string): string[] =>
  (value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .flatMap((item) => {
      try {
        return [new URL(item).origin];
      } catch {
        return [];
      }
    });

const readCookie = (request: Request, name: string): string | null => {
  const pair = (request.headers.get("cookie") ?? "")
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`));
  return pair ? pair.slice(name.length + 1) : null;
};

const missingOrigins = () =>
  new Response("ALLOWED_ORIGINS belum diatur", { status: 500 });

function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

const createOAuth = (env: Env) => {
  return new OAuthClient({
    id: env.GITHUB_OAUTH_ID,
    secret: env.GITHUB_OAUTH_SECRET,
    target: {
      tokenHost: "https://github.com",
      tokenPath: "/login/oauth/access_token",
      authorizePath: "/login/oauth/authorize",
    },
  });
};

const handleAuth = async (url: URL, env: Env) => {
  const provider = url.searchParams.get("provider");
  if (provider !== "github") {
    return new Response("Invalid provider", { status: 400 });
  }
  if (parseAllowedOrigins(env.ALLOWED_ORIGINS).length === 0) {
    return missingOrigins();
  }

  const repoIsPrivate =
    env.GITHUB_REPO_PRIVATE != undefined && env.GITHUB_REPO_PRIVATE !== "0";
  const repoScope = repoIsPrivate ? "repo,user" : "public_repo,user";

  const state = randomHex(16);
  const oauth2 = createOAuth(env);
  const authorizationUri = oauth2.authorizeURL({
    redirect_uri: `https://${url.hostname}/callback`,
    scope: repoScope,
    state,
  });

  const headers = new Headers({ location: authorizationUri });
  headers.append(
    "set-cookie",
    `${STATE_COOKIE}=${state}; Max-Age=600; ${COOKIE_ATTRS}`,
  );
  return new Response(null, { headers, status: 302 });
};

const scriptJson = (value: unknown) =>
  JSON.stringify(value).replace(/</g, "\\u003c");

const callbackScriptResponse = (
  status: string,
  token: string,
  allowedOrigins: string[],
) => {
  const message = `authorization:github:${status}:${JSON.stringify({ token })}`;
  const headers = new Headers({ "Content-Type": "text/html" });
  headers.append("set-cookie", `${STATE_COOKIE}=; Max-Age=0; ${COOKIE_ATTRS}`);
  return new Response(
    `
<html>
<head>
  <script>
    const allowed = ${scriptJson(allowedOrigins)};
    const message = ${scriptJson(message)};
    const receiveMessage = (event) => {
      if (!allowed.includes(event.origin)) return;
      event.source.postMessage(message, event.origin);
      window.removeEventListener("message", receiveMessage, false);
    }
    window.addEventListener("message", receiveMessage, false);
    window.opener.postMessage("authorizing:github", "*");
  </script>
  <body>
    <p>Authorizing Decap...</p>
  </body>
</head>
</html>
`,
    { headers },
  );
};

const handleCallback = async (request: Request, url: URL, env: Env) => {
  const allowedOrigins = parseAllowedOrigins(env.ALLOWED_ORIGINS);
  if (allowedOrigins.length === 0) {
    return missingOrigins();
  }

  const state = url.searchParams.get("state");
  const expectedState = readCookie(request, STATE_COOKIE);
  if (!state || !expectedState || state !== expectedState) {
    return new Response("Invalid state", { status: 400 });
  }

  const code = url.searchParams.get("code");
  if (!code) {
    return new Response("Missing code", { status: 400 });
  }

  const oauth2 = createOAuth(env);
  const accessToken = await oauth2.getToken({
    code,
    redirect_uri: `https://${url.hostname}/callback`,
  });
  return callbackScriptResponse("success", accessToken, allowedOrigins);
};

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);
    console.log(`url.pathname is ${url.pathname}`);
    if (url.pathname === "/auth") {
      return handleAuth(url, env);
    }
    if (url.pathname === "/callback") {
      return handleCallback(request, url, env);
    }
    return new Response("Hello 👋");
  },
};
