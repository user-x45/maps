const ALLOWED_DOMAINS = [
  "google.com",
  "gstatic.com",
  "googleapis.com",
  "googleusercontent.com",
  "ggpht.com",
];

const DEFAULT_HOST = "www.google.com";
const PREFIX = "/__p/";

const REWRITE_RE =
  /(https?:)?(\\?\/\\?\/)((?:[a-z0-9-]+\.)*(?:google\.com|gstatic\.com|googleapis\.com|googleusercontent\.com|ggpht\.com))(?![a-z0-9.-])/gi;

function isAllowed(host) {
  return ALLOWED_DOMAINS.some((d) => host === d || host.endsWith("." + d));
}

function parseTarget(url) {
  if (url.pathname.startsWith(PREFIX)) {
    const rest = url.pathname.slice(PREFIX.length);
    const idx = rest.indexOf("/");
    const host = (idx === -1 ? rest : rest.slice(0, idx)).toLowerCase();
    const path = idx === -1 ? "/" : rest.slice(idx);
    return { host, path };
  }
  return { host: DEFAULT_HOST, path: url.pathname };
}

function rewriteText(text, origin) {
  return text.replace(REWRITE_RE, (match, proto, slashes, host) => {
    if (slashes.includes("\\")) {
      const escOrigin = origin.replace(/\//g, "\\/");
      return `${escOrigin}\\/__p\\/${host}`;
    }
    return `${origin}/__p/${host}`;
  });
}

function rewriteLocation(location, upstreamUrl, origin) {
  try {
    const abs = new URL(location, upstreamUrl);
    if (!isAllowed(abs.hostname)) return location;
    if (abs.hostname === DEFAULT_HOST) {
      return origin + abs.pathname + abs.search + abs.hash;
    }
    return `${origin}${PREFIX}${abs.hostname}${abs.pathname}${abs.search}${abs.hash}`;
  } catch {
    return location;
  }
}

function buildRequestHeaders(request, upstreamUrl) {
  const headers = new Headers(request.headers);
  for (const key of [...headers.keys()]) {
    const k = key.toLowerCase();
    if (
      k === "host" ||
      k.startsWith("cf-") ||
      k.startsWith("x-forwarded") ||
      k === "x-real-ip"
    ) {
      headers.delete(key);
    }
  }
  headers.set("Host", upstreamUrl.host);
  const isGet = request.method === "GET" || request.method === "HEAD";
  const isDocument =
    isGet &&
    upstreamUrl.pathname === "/maps" &&
    (request.headers.get("Sec-Fetch-Dest") || "empty") === "empty";
  if (isDocument) {
    headers.delete("Origin");
    headers.delete("Referer");
    headers.set(
      "Accept",
      "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
    );
    headers.set("Sec-Fetch-Dest", "document");
    headers.set("Sec-Fetch-Mode", "navigate");
    headers.set("Sec-Fetch-Site", "none");
    headers.set("Sec-Fetch-User", "?1");
    headers.set("Upgrade-Insecure-Requests", "1");
  } else if (!isGet) {
    headers.set("Origin", upstreamUrl.origin);
    headers.set("Referer", upstreamUrl.origin + "/");
  } else {
    headers.set("Referer", upstreamUrl.origin + "/");
  }
  if (!headers.get("Accept-Language")) {
    headers.set("Accept-Language", "ja,en;q=0.8");
  }
  const cookie = headers.get("Cookie") || "";
  if (!/(^|;\s*)CONSENT=/.test(cookie)) {
    headers.set("Cookie", (cookie ? cookie + "; " : "") + "CONSENT=YES+cb");
  }
  return headers;
}

function buildResponseHeaders(upstream, upstreamUrl, origin) {
  const headers = new Headers(upstream.headers);
  for (const h of [
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "strict-transport-security",
    "report-to",
    "content-length",
    "content-encoding",
    "set-cookie",
  ]) {
    headers.delete(h);
  }
  const cookies =
    typeof upstream.headers.getSetCookie === "function"
      ? upstream.headers.getSetCookie()
      : [];
  for (const c of cookies) {
    headers.append(
      "Set-Cookie",
      c
        .replace(/;\s*Domain=[^;]*/gi, "")
        .replace(/;\s*SameSite=[^;]*/gi, "; SameSite=Lax")
    );
  }
  const location = headers.get("Location");
  if (location) {
    headers.set("Location", rewriteLocation(location, upstreamUrl, origin));
  }
  headers.set("Access-Control-Allow-Origin", "*");
  return headers;
}

function isTextType(contentType) {
  return /(text\/html|javascript|text\/css|application\/json|text\/plain|xml)/i.test(
    contentType
  );
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const origin = url.origin;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
          "Access-Control-Allow-Headers": "*",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    if (url.pathname === "/") {
      return new Response("OK", {
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }

    if (url.pathname === "/favicon.ico") {
      return new Response(null, { status: 204 });
    }

    const { host, path } = parseTarget(url);
    if (!isAllowed(host)) {
      return new Response("Forbidden host", {
        status: 403,
        headers: { "Access-Control-Allow-Origin": "*" },
      });
    }

    const upstreamUrl = new URL(`https://${host}${path}${url.search}`);
    const init = {
      method: request.method,
      headers: buildRequestHeaders(request, upstreamUrl),
      redirect: "manual",
    };
    if (request.method !== "GET" && request.method !== "HEAD") {
      init.body = request.body;
    }

    let upstream;
    try {
      upstream = await fetch(upstreamUrl.toString(), init);
    } catch (e) {
      return new Response("Upstream fetch failed", {
        status: 502,
        headers: { "Access-Control-Allow-Origin": "*" },
      });
    }

    const headers = buildResponseHeaders(upstream, upstreamUrl, origin);
    const contentType = upstream.headers.get("Content-Type") || "";

    if (isTextType(contentType)) {
      const body = rewriteText(await upstream.text(), origin);
      return new Response(body, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers,
      });
    }

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers,
    });
  },
};
