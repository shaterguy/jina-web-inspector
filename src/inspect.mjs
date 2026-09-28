import crypto from "node:crypto";
import { parse } from "node-html-parser";
import { sanitizeUrl, scrubText } from "./jina.mjs";

const ATTR_ALLOW = new Set(["id","class","role","name","type","placeholder","title","alt","for","method","target","tabindex","autocomplete","disabled","required","readonly","checked","selected","loading","width","height","sandbox","allow","rel","as","media","crossorigin","referrerpolicy","aria-hidden"]);
const INLINE_STYLE_ALLOW = new Set(["display","visibility","opacity","position","width","height","min-width","min-height","max-width","max-height","overflow","overflow-x","overflow-y","pointer-events","z-index"]);
const SECRET_META_NAME = /(csrf|xsrf|token|nonce|secret|auth|session|credential|api[_-]?key)/i;

export function sha256Text(value) {
  return crypto.createHash("sha256").update(String(value ?? "")).digest("hex");
}

function cleanText(value, max = 180) {
  const s = String(value ?? "").replace(/\s+/g, " ").trim();
  return scrubText(s, max);
}

function rootOf(html) {
  return parse(html, { comment: false, blockTextElements: { script: true, noscript: true, style: true, pre: true } });
}

function tag(el) { return String(el?.tagName || "").toLowerCase(); }

function resolveSafe(value, baseUrl) {
  if (!value) return "";
  try { return sanitizeUrl(new URL(value, baseUrl).toString()); } catch { return scrubText(value, 500); }
}

function parseInlineStyle(style) {
  const out = {};
  for (const part of String(style || "").split(";")) {
    const i = part.indexOf(":");
    if (i < 1) continue;
    const k = part.slice(0, i).trim().toLowerCase();
    if (!INLINE_STYLE_ALLOW.has(k)) continue;
    out[k] = scrubText(part.slice(i + 1).trim(), 160);
  }
  return out;
}

function publicAttrs(el, baseUrl) {
  const out = {};
  for (const [rawName, rawValue] of Object.entries(el?.attributes || {})) {
    const name = rawName.toLowerCase();
    if (name === "value" || name === "srcdoc" || name === "nonce" || name.startsWith("on")) continue;
    if (!(ATTR_ALLOW.has(name) || name === "href" || name === "src" || name === "action" || name === "data-testid" || name === "data-test" || name === "data-qa" || name.startsWith("aria-"))) continue;
    if (name === "href" || name === "src" || name === "action") out[name] = resolveSafe(rawValue, baseUrl);
    else out[name] = scrubText(rawValue, 300);
  }
  const style = parseInlineStyle(el?.getAttribute?.("style"));
  if (Object.keys(style).length) out.inlineStyle = style;
  return out;
}

function parentChain(el, baseUrl, max = 5) {
  const out = [];
  let cur = el?.parentNode;
  while (cur && out.length < max) {
    if (cur.tagName) out.push({ tag: tag(cur), attrs: publicAttrs(cur, baseUrl) });
    cur = cur.parentNode;
  }
  return out;
}

function formSummary(form, baseUrl) {
  if (!form) return null;
  return {
    tag: "form",
    id: form.getAttribute("id") || null,
    name: form.getAttribute("name") || null,
    method: (form.getAttribute("method") || "get").toLowerCase(),
    action: resolveSafe(form.getAttribute("action") || baseUrl, baseUrl),
  };
}

function queryAllSafe(root, selector) {
  try { return { nodes: root.querySelectorAll(selector), error: null }; }
  catch (error) { return { nodes: [], error: String(error?.message || error) }; }
}


export function sanitizeRenderedHtmlForOutput(html, { baseUrl = "" } = {}) {
  const root = rootOf(html);
  for (const el of root.querySelectorAll("*")) {
    const attrs = Object.keys(el.attributes || {});
    for (const rawName of attrs) {
      const name = rawName.toLowerCase();
      if (name === "nonce" || name === "srcdoc" || name.startsWith("on")) el.removeAttribute(rawName);
      if (name === "value" && ["input","option","button"].includes(tag(el))) el.removeAttribute(rawName);
      if (["href","src","action","formaction","poster"].includes(name)) {
        const old = el.getAttribute(rawName);
        if (old) el.setAttribute(rawName, resolveSafe(old, baseUrl));
      }
      if (name === "srcset") {
        const old = el.getAttribute(rawName);
        if (old) el.setAttribute(rawName, sanitizeSrcset(old, baseUrl));
      }
    }
    if (tag(el) === "textarea") {
      const n = (el.textContent || "").length;
      if (n) el.setAttribute("data-jwi-value-redacted", "true");
      el.set_content("");
    }
    if (tag(el) === "script" && !el.getAttribute("src")) {
      const body = el.textContent || "";
      if (body) {
        el.setAttribute("data-jwi-inline-length", String(body.length));
        el.setAttribute("data-jwi-inline-sha256", sha256Text(body));
      }
      el.set_content("");
    }
    if (tag(el) === "meta") {
      const key = el.getAttribute("name") || el.getAttribute("property") || el.getAttribute("http-equiv") || "";
      if (SECRET_META_NAME.test(key) && el.hasAttribute("content")) el.setAttribute("content", "[redacted]");
    }
  }
  return root.toString();
}

export function inspectElements(html, { selectors, maxMatches = 25, includeText = true, baseUrl = "" }) {
  const root = rootOf(html);
  const results = [];
  let remaining = maxMatches;
  for (const selector of [...new Set(selectors)]) {
    if (remaining <= 0) break;
    const { nodes, error } = queryAllSafe(root, selector);
    if (error) {
      results.push({ selector, error, matches: [] });
      continue;
    }
    const matches = [];
    for (const el of nodes.slice(0, remaining)) {
      const form = el.closest?.("form") || null;
      matches.push({
        tag: tag(el),
        attrs: publicAttrs(el, baseUrl),
        text: includeText && !["input","textarea","select","option"].includes(tag(el)) ? cleanText(el.textContent, 220) : undefined,
        parentChain: parentChain(el, baseUrl),
        closestForm: formSummary(form, baseUrl),
      });
      remaining -= 1;
      if (remaining <= 0) break;
    }
    results.push({ selector, count: nodes.length, returned: matches.length, matches });
  }
  return {
    capability: "rendered-html-structure",
    maxMatches,
    results,
    limitations: ["No live bounding boxes, focus state, checkVisibility(), or computed styles: anonymous Jina Reader does not permit the script injection required for those probes."],
  };
}

export function inspectDom(html, { baseUrl = "", maxHeadings = 40, maxLandmarks = 40 } = {}) {
  const root = rootOf(html);
  const all = root.querySelectorAll("*");
  const tagCounts = {};
  for (const el of all) {
    const t = tag(el);
    tagCounts[t] = (tagCounts[t] || 0) + 1;
  }
  const sortedTags = Object.entries(tagCounts).sort((a,b) => b[1]-a[1]).map(([name,count]) => ({name,count}));
  const headings = root.querySelectorAll("h1,h2,h3,h4,h5,h6").slice(0, maxHeadings).map(el => ({level: Number(tag(el).slice(1)), id: el.getAttribute("id") || null, text: cleanText(el.textContent, 240)}));
  const landmarks = root.querySelectorAll("main,nav,header,footer,aside,[role]").slice(0, maxLandmarks).map(el => ({tag: tag(el), role: el.getAttribute("role") || null, id: el.getAttribute("id") || null, label: cleanText(el.getAttribute("aria-label") || el.getAttribute("title") || "", 180)}));
  const htmlEl = root.querySelector("html");
  return {
    capability: "rendered-html-structure",
    totalElements: all.length,
    language: htmlEl?.getAttribute("lang") || null,
    counts: {
      forms: root.querySelectorAll("form").length,
      controls: root.querySelectorAll("input,textarea,select,button").length,
      links: root.querySelectorAll("a[href]").length,
      images: root.querySelectorAll("img").length,
      frames: root.querySelectorAll("iframe,frame").length,
      scripts: root.querySelectorAll("script").length,
      stylesheets: root.querySelectorAll('style,link[rel~="stylesheet"]').length,
    },
    tagCounts: sortedTags.slice(0, 80),
    headings,
    landmarks,
    baseUrl: sanitizeUrl(baseUrl),
  };
}

export function inspectFrames(html, { baseUrl = "", maxFrames = 50 } = {}) {
  const root = rootOf(html);
  const frames = root.querySelectorAll("iframe,frame");
  return {
    capability: "frame-element-metadata",
    count: frames.length,
    returned: Math.min(frames.length, maxFrames),
    frames: frames.slice(0, maxFrames).map(el => ({
      tag: tag(el),
      id: el.getAttribute("id") || null,
      name: el.getAttribute("name") || null,
      src: resolveSafe(el.getAttribute("src"), baseUrl),
      title: cleanText(el.getAttribute("title"), 200) || null,
      loading: el.getAttribute("loading") || null,
      sandbox: scrubText(el.getAttribute("sandbox") || "", 300) || null,
      allow: scrubText(el.getAttribute("allow") || "", 300) || null,
      width: el.getAttribute("width") || null,
      height: el.getAttribute("height") || null,
      hasSrcdoc: el.hasAttribute("srcdoc"),
    })),
    limitations: ["Iframe body merging is not available on the anonymous Jina Reader tier, so this tool intentionally returns frame element metadata only."],
  };
}

function scrubCssSnippet(value, baseUrl, max = 900) {
  let s = scrubText(value, max * 2);
  s = s.replace(/url\((['"]?)([^)'"\s]+)\1\)/gi, (_m, q, url) => `url(${q}${resolveSafe(url, baseUrl)}${q})`);
  return scrubText(s, max);
}

export function inspectStyles(html, { baseUrl = "", selector, maxSheets = 30, maxElements = 30 } = {}) {
  const root = rootOf(html);
  const styleEls = root.querySelectorAll("style").slice(0, maxSheets);
  const links = root.querySelectorAll('link[rel~="stylesheet"]').slice(0, maxSheets);
  const targetSelector = selector || "[style]";
  const q = queryAllSafe(root, targetSelector);
  return {
    capability: "rendered-html-style-sources",
    inlineStylesheets: styleEls.map((el, index) => {
      const css = el.textContent || "";
      return { index, media: el.getAttribute("media") || null, length: css.length, sha256: sha256Text(css), snippet: scrubCssSnippet(css, baseUrl, 900) };
    }),
    linkedStylesheets: links.map(el => ({ href: resolveSafe(el.getAttribute("href"), baseUrl), media: el.getAttribute("media") || null, type: el.getAttribute("type") || null })),
    styledElements: q.error ? [] : q.nodes.slice(0, maxElements).map(el => ({ tag: tag(el), id: el.getAttribute("id") || null, class: scrubText(el.getAttribute("class") || "", 300) || null, inlineStyle: parseInlineStyle(el.getAttribute("style")) })),
    selectorError: q.error,
    limitations: ["This is source/inline style inspection, not browser CSSOM or computed-style inspection."],
  };
}

function sanitizeSrcset(srcset, baseUrl) {
  if (!srcset) return "";
  return srcset.split(",").slice(0, 20).map(part => {
    const bits = part.trim().split(/\s+/);
    const u = resolveSafe(bits.shift(), baseUrl);
    return [u, ...bits].join(" ");
  }).join(", ");
}

export function inspectResources(html, { baseUrl = "", maxPerType = 80 } = {}) {
  const root = rootOf(html);
  const scripts = root.querySelectorAll("script");
  const links = root.querySelectorAll("link[href]");
  const images = root.querySelectorAll("img");
  const media = root.querySelectorAll("video,audio,source");
  return {
    capability: "rendered-html-resource-inventory",
    counts: { scripts: scripts.length, links: links.length, images: images.length, media: media.length },
    scripts: scripts.slice(0, maxPerType).map(el => {
      const src = el.getAttribute("src");
      const inline = src ? "" : (el.textContent || "");
      return { src: resolveSafe(src, baseUrl) || null, type: el.getAttribute("type") || null, async: el.hasAttribute("async"), defer: el.hasAttribute("defer"), inlineLength: inline.length || 0, inlineSha256: inline ? sha256Text(inline) : null };
    }),
    links: links.slice(0, maxPerType).map(el => ({ rel: scrubText(el.getAttribute("rel") || "", 160), href: resolveSafe(el.getAttribute("href"), baseUrl), as: el.getAttribute("as") || null, type: el.getAttribute("type") || null, media: el.getAttribute("media") || null })),
    images: images.slice(0, maxPerType).map(el => ({ src: resolveSafe(el.getAttribute("src"), baseUrl), srcset: sanitizeSrcset(el.getAttribute("srcset"), baseUrl), alt: cleanText(el.getAttribute("alt"), 240), loading: el.getAttribute("loading") || null, width: el.getAttribute("width") || null, height: el.getAttribute("height") || null })),
    media: media.slice(0, maxPerType).map(el => ({ tag: tag(el), src: resolveSafe(el.getAttribute("src"), baseUrl), type: el.getAttribute("type") || null })),
  };
}

function labelMap(root) {
  const m = new Map();
  for (const label of root.querySelectorAll("label")) {
    const forId = label.getAttribute("for");
    if (forId) m.set(forId, cleanText(label.textContent, 200));
  }
  return m;
}

export function inspectForms(html, { baseUrl = "", maxForms = 30, maxControls = 120 } = {}) {
  const root = rootOf(html);
  const labels = labelMap(root);
  const forms = root.querySelectorAll("form");
  let remaining = maxControls;
  const formResults = [];
  for (const form of forms.slice(0, maxForms)) {
    const controls = [];
    for (const el of form.querySelectorAll("input,textarea,select,button").slice(0, remaining)) {
      const id = el.getAttribute("id") || null;
      controls.push({
        tag: tag(el), id, name: el.getAttribute("name") || null, type: el.getAttribute("type") || (tag(el) === "button" ? "submit" : null),
        role: el.getAttribute("role") || null, label: cleanText(el.getAttribute("aria-label") || (id ? labels.get(id) : "") || el.getAttribute("title") || "", 200) || null,
        placeholder: cleanText(el.getAttribute("placeholder"), 200) || null, autocomplete: el.getAttribute("autocomplete") || null,
        required: el.hasAttribute("required"), disabled: el.hasAttribute("disabled"), readOnly: el.hasAttribute("readonly"),
        optionCount: tag(el) === "select" ? el.querySelectorAll("option").length : undefined,
        selectedCount: tag(el) === "select" ? el.querySelectorAll("option[selected]").length : undefined,
      });
      remaining -= 1;
      if (remaining <= 0) break;
    }
    formResults.push({ ...formSummary(form, baseUrl), controls });
    if (remaining <= 0) break;
  }
  const unowned = remaining > 0 ? root.querySelectorAll("input,textarea,select,button").filter(el => !el.closest?.("form")).slice(0, remaining).map(el => ({ tag: tag(el), id: el.getAttribute("id") || null, name: el.getAttribute("name") || null, type: el.getAttribute("type") || null, role: el.getAttribute("role") || null, placeholder: cleanText(el.getAttribute("placeholder"), 200) || null, required: el.hasAttribute("required"), disabled: el.hasAttribute("disabled"), readOnly: el.hasAttribute("readonly") })) : [];
  return {
    capability: "rendered-html-form-inventory",
    formCount: forms.length,
    forms: formResults,
    unownedControls: unowned,
    privacy: "Control values, hidden values, textarea contents, and option values are intentionally omitted.",
  };
}

function inferredRole(el) {
  const explicit = el.getAttribute("role");
  if (explicit) return explicit;
  const t = tag(el);
  if (/^h[1-6]$/.test(t)) return "heading";
  if (t === "a" && el.getAttribute("href")) return "link";
  if (t === "button") return "button";
  if (t === "select") return "combobox";
  if (t === "textarea") return "textbox";
  if (t === "input") {
    const type = (el.getAttribute("type") || "text").toLowerCase();
    if (["checkbox","radio","button","submit","reset","range"].includes(type)) return type === "submit" || type === "reset" ? "button" : type;
    if (type !== "hidden") return "textbox";
  }
  if (t === "nav") return "navigation";
  if (t === "main") return "main";
  if (t === "aside") return "complementary";
  if (t === "img") return "img";
  return null;
}

export function inspectAccessibility(html, { maxNodes = 120 } = {}) {
  const root = rootOf(html);
  const labels = labelMap(root);
  const candidates = root.querySelectorAll('h1,h2,h3,h4,h5,h6,a[href],button,input,textarea,select,img,[role],[aria-label],[aria-labelledby]');
  const nodes = [];
  for (const el of candidates) {
    const role = inferredRole(el);
    if (!role) continue;
    const id = el.getAttribute("id") || null;
    const label = cleanText(el.getAttribute("aria-label") || (id ? labels.get(id) : "") || el.getAttribute("alt") || el.getAttribute("title") || (!["input","textarea","select"].includes(tag(el)) ? el.textContent : ""), 220);
    nodes.push({ tag: tag(el), role, id, label: label || null, ariaLabelledby: scrubText(el.getAttribute("aria-labelledby") || "", 200) || null, ariaHidden: el.getAttribute("aria-hidden") || null, tabIndex: el.getAttribute("tabindex") || null, disabled: el.hasAttribute("disabled") || el.getAttribute("aria-disabled") === "true", headingLevel: /^h[1-6]$/.test(tag(el)) ? Number(tag(el).slice(1)) : undefined });
    if (nodes.length >= maxNodes) break;
  }
  return {
    capability: "html-aria-semantic-inventory",
    candidateCount: candidates.length,
    returned: nodes.length,
    nodes,
    limitations: ["This is derived from rendered HTML and ARIA attributes. It is not the Chromium accessibility protocol tree and does not prove actual focusability or screen-reader exposure."],
  };
}

export function inspectPageMetadata(html, { baseUrl = "", jina = {} } = {}) {
  const root = rootOf(html);
  const htmlEl = root.querySelector("html");
  const canonical = root.querySelector('link[rel="canonical"]');
  const metas = root.querySelectorAll("meta").slice(0, 120).map(el => {
    const name = el.getAttribute("name") || el.getAttribute("property") || el.getAttribute("http-equiv") || null;
    let content = el.getAttribute("content") || "";
    if (SECRET_META_NAME.test(name || "")) content = "[redacted]";
    else if (/^https?:\/\//i.test(content)) content = resolveSafe(content, baseUrl);
    else content = scrubText(content, 500);
    return { name, content };
  });
  return {
    capability: "rendered-html-page-metadata",
    title: cleanText(root.querySelector("title")?.textContent || jina.title || "", 300),
    finalUrl: sanitizeUrl(jina.finalUrl || baseUrl),
    publishedTime: jina.publishedTime || null,
    httpStatus: jina.httpStatus ?? null,
    html: { lang: htmlEl?.getAttribute("lang") || null, dir: htmlEl?.getAttribute("dir") || null },
    canonical: resolveSafe(canonical?.getAttribute("href"), baseUrl) || null,
    meta: metas,
    jinaMetadata: Object.fromEntries(Object.entries(jina.metadata || {}).filter(([k]) => !SECRET_META_NAME.test(k)).slice(0, 120).map(([k,v]) => [k, typeof v === "string" && /^https?:\/\//i.test(v) ? resolveSafe(v, baseUrl) : scrubText(typeof v === "string" ? v : JSON.stringify(v), 500)])),
  };
}
