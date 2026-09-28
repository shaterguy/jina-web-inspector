import net from "node:net";

export const UPSTREAM = "https://r.jina.ai/";
export const MAX_INSPECT_HTML_CHARS = 2_000_000;
export const MAX_SCREENSHOT_BYTES = 12 * 1024 * 1024;

const SECRET_PARAM = /(token|auth|authorization|api[_-]?key|key|secret|session|sid|jwt|signature|credential|password|passwd)/i;

export function sanitizeUrl(value, base) {
  if (!value) return "";
  try {
    const u = base ? new URL(value, base) : new URL(value);
    u.username = "";
    u.password = "";
    u.hash = "";
    if (u.search) u.search = "";
    return u.toString();
  } catch {
    return String(value).replace(/([?&][^=&#]*(?:token|key|secret|auth|session|signature|credential)[^=&#]*=)[^&#]*/gi, "$1[redacted]");
  }
}

export function scrubText(value, max = 1000) {
  let s = String(value ?? "");
  s = s.replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [redacted]");
  s = s.replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "[jwt-redacted]");
  s = s.replace(/([?&]([^=&#]+)=)([^&#]*)/g, (m, prefix, name) => SECRET_PARAM.test(name) ? `${prefix}[redacted]` : m);
  if (s.length > max) s = `${s.slice(0, max)}…`;
  return s;
}

function isPrivateIpv4(host) {
  const p = host.split(".").map(Number);
  if (p.length !== 4 || p.some(x => !Number.isInteger(x) || x < 0 || x > 255)) return false;
  return p[0] === 10 || p[0] === 127 || p[0] === 0 ||
    (p[0] === 169 && p[1] === 254) ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
}

function isPrivateIpv6(host) {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  return h === "::1" || h === "::" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe8") || h.startsWith("fe9") || h.startsWith("fea") || h.startsWith("feb");
}

export function assertPublicHttpUrl(value) {
  let u;
  try { u = new URL(value); } catch { throw new Error("URL must be a valid absolute URL"); }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("Only http and https URLs are allowed");
  const host = u.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) throw new Error("Loopback/local hostnames are not allowed");
  const ip = net.isIP(host.replace(/^\[|\]$/g, ""));
  if ((ip === 4 && isPrivateIpv4(host)) || (ip === 6 && isPrivateIpv6(host))) throw new Error("Private or loopback IP addresses are not allowed");
  return u.toString();
}

function readerHeaders({ withAllLinks = false, withAllImages = false } = {}) {
  const headers = {
    Accept: "application/json",
    "Content-Type": "application/json",
    "X-Md-Link-Style": "discarded",
  };
  if (withAllLinks) headers["X-With-Links-Summary"] = "all";
  if (withAllImages) headers["X-With-Images-Summary"] = "true";
  else headers["X-Retain-Images"] = "none";
  return headers;
}

export async function callJina(body, { timeoutMs = 45_000, headers = {} } = {}) {
  const response = await fetch(UPSTREAM, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const raw = await response.text();
  let payload;
  try { payload = JSON.parse(raw); } catch { throw new Error(`Jina Reader returned non-JSON data: ${scrubText(raw, 500)}`); }
  if (!response.ok) {
    const msg = payload?.readableMessage || payload?.message || raw;
    throw new Error(`Jina Reader HTTP ${response.status}: ${scrubText(msg, 700)}`);
  }
  if (!payload?.data) throw new Error("Jina Reader response did not contain data");
  return { data: payload.data, response };
}

export async function readOne(url, options = {}) {
  const safeUrl = assertPublicHttpUrl(url);
  const { data, response } = await callJina({ url: safeUrl }, {
    timeoutMs: 30_000,
    headers: readerHeaders(options),
  });
  const result = {
    url: sanitizeUrl(data.url || safeUrl),
    title: data.title || "",
    publishedTime: data.publishedTime || null,
    content: data.content || "",
    httpStatus: data.httpStatus ?? null,
    warning: data.warning || null,
    usage: data.usage || null,
    rateLimit: {
      limit: response.headers.get("x-ratelimit-limit"),
      remaining: response.headers.get("x-ratelimit-remaining"),
    },
  };
  if (options.withAllLinks && data.links) result.links = data.links;
  if (options.withAllImages && data.images) result.images = data.images;
  return result;
}

export async function fetchRenderedHtml(url, { selector, includeShadowDom = true, fresh = false, viewport } = {}) {
  const safeUrl = assertPublicHttpUrl(url);
  const body = {
    url: safeUrl,
    respondWith: "html",
    withShadowDom: includeShadowDom,
    noCache: fresh,
  };
  if (selector) body.targetSelector = selector;
  if (viewport) body.viewport = viewport;
  const { data } = await callJina(body, { timeoutMs: 45_000 });
  const html = data.html || "";
  if (html.length > MAX_INSPECT_HTML_CHARS) {
    throw new Error(`Rendered HTML is too large to inspect safely (${html.length} chars; limit ${MAX_INSPECT_HTML_CHARS}). Use get_rendered_html with a selector or a narrower page.`);
  }
  return {
    sourceUrl: safeUrl,
    finalUrl: sanitizeUrl(data.url || safeUrl),
    title: data.title || "",
    publishedTime: data.publishedTime || null,
    httpStatus: data.httpStatus ?? null,
    metadata: data.metadata || {},
    html,
  };
}

export async function captureScreenshot(url, { fullPage = false, fresh = false, viewport } = {}) {
  const safeUrl = assertPublicHttpUrl(url);
  const body = { url: safeUrl, respondWith: fullPage ? "pageshot" : "screenshot", noCache: fresh };
  if (viewport) body.viewport = viewport;
  const { data } = await callJina(body, { timeoutMs: 60_000 });
  const imageUrl = data.pageshotUrl || data.screenshotUrl;
  if (!imageUrl) throw new Error("Jina Reader did not return a screenshot URL");
  const imageResponse = await fetch(imageUrl, { signal: AbortSignal.timeout(20_000) });
  if (!imageResponse.ok) throw new Error(`Screenshot download failed with HTTP ${imageResponse.status}`);
  const contentLength = Number(imageResponse.headers.get("content-length") || 0);
  if (contentLength > MAX_SCREENSHOT_BYTES) throw new Error(`Screenshot is too large (${contentLength} bytes; limit ${MAX_SCREENSHOT_BYTES})`);
  const bytes = new Uint8Array(await imageResponse.arrayBuffer());
  if (bytes.byteLength > MAX_SCREENSHOT_BYTES) throw new Error(`Screenshot is too large (${bytes.byteLength} bytes; limit ${MAX_SCREENSHOT_BYTES})`);
  return {
    metadata: {
      url: sanitizeUrl(data.url || safeUrl),
      title: data.title || "",
      httpStatus: data.httpStatus ?? null,
      fullPage,
      bytes: bytes.byteLength,
    },
    data: Buffer.from(bytes).toString("base64"),
    mimeType: imageResponse.headers.get("content-type")?.split(";")[0] || "image/jpeg",
  };
}
