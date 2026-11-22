// test/index.spec.ts
import {
  SELF,
  createExecutionContext,
  waitOnExecutionContext,
} from "cloudflare:test";
import { describe, it, expect, vi, afterEach } from "vitest";
import worker, { parseAllowedOrigins } from "../src/index";

const ADMIN = "https://admin.example.com";
const env = {
  GITHUB_OAUTH_ID: "test-id",
  GITHUB_OAUTH_SECRET: "test-secret",
  ALLOWED_ORIGINS: ADMIN,
};

const call = async (
  path: string,
  init: RequestInit = {},
  e: Record<string, string | undefined> = env,
) => {
  const ctx = createExecutionContext();
  const response = await worker.fetch(
    new Request(`https://proxy.example.com${path}`, {
      redirect: "manual",
      ...init,
    }),
    e as any,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return response;
};

const stateFromLocation = (location: string) =>
  new URL(location).searchParams.get("state")!;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("GET /", () => {
  it("responds with no-op (Hello)", async () => {
    const response = await SELF.fetch("https://example.com");
    expect(await response.text()).toMatchInlineSnapshot(`"Hello 👋"`);
  });
});

describe("parseAllowedOrigins", () => {
  it("memisahkan koma, merapikan spasi, dan membuang garis miring akhir", () => {
    expect(
      parseAllowedOrigins(" https://a.example.com/ , http://localhost:8080 "),
    ).toEqual(["https://a.example.com", "http://localhost:8080"]);
  });
  it("membuang nilai kosong, wildcard, dan yang bukan URL", () => {
    expect(parseAllowedOrigins("*, bogus, ,")).toEqual([]);
    expect(parseAllowedOrigins(undefined)).toEqual([]);
    expect(parseAllowedOrigins("")).toEqual([]);
  });
});

describe("GET /auth", () => {
  it("menolak bila ALLOWED_ORIGINS kosong (gagal tertutup)", async () => {
    const response = await call(
      "/auth?provider=github",
      {},
      { ...env, ALLOWED_ORIGINS: "" },
    );
    expect(response.status).toBe(500);
    expect(response.headers.get("location")).toBeNull();
    expect(await response.text()).toContain("ALLOWED_ORIGINS");
  });

  it("menolak provider selain github", async () => {
    expect((await call("/auth?provider=gitlab")).status).toBe(400);
  });

  it("mengarahkan ke GitHub dengan state acak 32 hex yang sama dengan cookie", async () => {
    const response = await call("/auth?provider=github");
    expect(response.status).toBe(302);
    const location = response.headers.get("location")!;
    expect(
      location.startsWith("https://github.com/login/oauth/authorize?"),
    ).toBe(true);
    expect(location).toContain("client_id=test-id");
    expect(location).toContain(
      "redirect_uri=https://proxy.example.com/callback&",
    );
    const state = stateFromLocation(location);
    expect(state).toMatch(/^[0-9a-f]{32}$/);
    const cookie = response.headers.get("set-cookie")!;
    expect(cookie).toContain(`oauth_state=${state}`);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Max-Age=600");
  });

  it("memberi state berbeda di tiap permintaan", async () => {
    const a = stateFromLocation(
      (await call("/auth?provider=github")).headers.get("location")!,
    );
    const b = stateFromLocation(
      (await call("/auth?provider=github")).headers.get("location")!,
    );
    expect(a).not.toEqual(b);
  });
});

describe("GET /callback", () => {
  const stubGithub = () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify({ access_token: "some-access-token" }), {
          headers: { "Content-Type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  };
  const STATE = "a".repeat(32);

  it("menolak tanpa cookie state dan tidak menghubungi GitHub", async () => {
    const fetchMock = stubGithub();
    const response = await call(
      `/callback?provider=github&code=abc&state=${STATE}`,
    );
    expect(response.status).toBe(400);
    expect(await response.text()).toContain("Invalid state");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("menolak bila state di URL berbeda dari cookie", async () => {
    const fetchMock = stubGithub();
    const response = await call(
      `/callback?provider=github&code=abc&state=${"b".repeat(32)}`,
      { headers: { cookie: `oauth_state=${STATE}` } },
    );
    expect(response.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("menolak bila parameter state tidak ada", async () => {
    const fetchMock = stubGithub();
    const response = await call("/callback?provider=github&code=abc", {
      headers: { cookie: `oauth_state=${STATE}` },
    });
    expect(response.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("menolak bila ALLOWED_ORIGINS kosong", async () => {
    const fetchMock = stubGithub();
    const response = await call(
      `/callback?provider=github&code=abc&state=${STATE}`,
      { headers: { cookie: `oauth_state=${STATE}` } },
      { ...env, ALLOWED_ORIGINS: "" },
    );
    expect(response.status).toBe(500);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("menukar kode hanya ke github.com dan menghapus cookie state", async () => {
    const fetchMock = stubGithub();
    const response = await call(
      `/callback?provider=github&code=abc&state=${STATE}`,
      { headers: { cookie: `x=1; oauth_state=${STATE}` } },
    );
    expect(response.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(url).toBe("https://github.com/login/oauth/access_token");
    expect(JSON.parse(init.body as string)).toMatchObject({
      client_id: "test-id",
      client_secret: "test-secret",
      code: "abc",
    });
    expect(response.headers.get("set-cookie")).toMatch(
      /oauth_state=;.*Max-Age=0/,
    );
  });

  it("meloloskan < di dalam skrip agar </script> tidak menutup tag", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify({ access_token: "x</script><img>" }), {
            headers: { "Content-Type": "application/json" },
          }),
      ),
    );
    const response = await call(
      `/callback?provider=github&code=abc&state=${STATE}`,
      { headers: { cookie: `oauth_state=${STATE}` } },
    );
    const body = await response.text();
    expect(body).not.toContain("x</script>");
    expect(body).toContain("x\\u003c/script>");
  });

  it("halaman balasan hanya mengirim token ke origin yang diizinkan", async () => {
    stubGithub();
    const response = await call(
      `/callback?provider=github&code=abc&state=${STATE}`,
      { headers: { cookie: `oauth_state=${STATE}` } },
    );
    const body = await response.text();
    expect(body).toContain(
      'window.opener.postMessage("authorizing:github", "*");',
    );
    expect(body).toContain(`const allowed = ["${ADMIN}"];`);
    expect(body).toContain("if (!allowed.includes(event.origin)) return;");
    expect(body).toContain("event.source.postMessage(message, event.origin);");
    expect(body.match(/"\*"/g)).toHaveLength(1);
    expect(body).toContain(
      'authorization:github:success:{\\"token\\":\\"some-access-token\\"}',
    );
  });
});
