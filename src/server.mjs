import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { readOne, fetchRenderedHtml, captureScreenshot } from "./jina.mjs";
import { sanitizeRenderedHtmlForOutput, inspectElements, inspectDom, inspectFrames, inspectStyles, inspectResources, inspectForms, inspectAccessibility, inspectPageMetadata } from "./inspect.mjs";

export const SERVICE = "jina-web-inspector";
export const VERSION = "0.2.0-dev1";
export const TOOL_NAMES = Object.freeze([
  "get_capabilities","read_url","capture_screenshot","get_rendered_html","inspect_elements","inspect_dom","inspect_frames","inspect_styles","inspect_resources","inspect_forms","inspect_accessibility","inspect_page_metadata"
]);

const annotations = Object.freeze({ readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true });
const singleUrl = z.string().url();
const urlInput = z.union([singleUrl, z.array(singleUrl).min(1).max(5)]);
const fresh = z.boolean().default(false).optional();
const shadow = z.boolean().default(true).optional();
const viewportSchema = z.object({ width: z.number().int().min(320).max(1920), height: z.number().int().min(320).max(2160) }).optional();

function textResult(value) { return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] }; }
function errorResult(error) { return { content: [{ type: "text", text: JSON.stringify({ error: String(error?.message || error) }, null, 2) }], isError: true }; }

async function rendered(url, opts = {}) {
  return fetchRenderedHtml(url, opts);
}

export function createMcpServer() {
  const server = new McpServer({ name: SERVICE, version: VERSION });

  server.registerTool("get_capabilities", {
    title: "get_capabilities",
    description: "Describe what this Jina-backed inspector can and cannot observe on the current anonymous Reader tier.",
    inputSchema: {}, annotations,
  }, async () => textResult({
    service: SERVICE, version: VERSION, upstream: "official Jina Reader API",
    available: {
      markdownRead: true, renderedHtml: true, selectorTargeting: true, screenshot: true, fullPageScreenshot: true,
      viewportControl: true, shadowDomFlattening: true, structuralElementInspection: true, formAndResourceInventory: true, htmlAriaSemantics: true,
    },
    unavailableWithoutJinaApiKey: {
      arbitraryOrFixedScriptInjection: true, iframeContentMerging: true, liveDomGeometry: true, computedStyles: true,
      focusAndSelectionState: true, performanceApi: true, consoleEvents: true, networkEvents: true, storageValues: true, chromiumAxTree: true,
    },
    securityBoundary: ["No arbitrary JavaScript tool", "No cookie/auth/custom-header input", "No form values or inline script bodies", "Structured URLs drop credentials, query strings, and fragments"],
  }));

  server.registerTool("read_url", {
    title: "read_url",
    description: "Read one public web page/PDF, or up to five URLs, through anonymous Jina Reader and return clean Markdown. Preserves the prior jina-reader TMCP behavior.",
    inputSchema: { url: urlInput, withAllLinks: z.boolean().default(false).optional(), withAllImages: z.boolean().default(false).optional() }, annotations,
  }, async ({ url, withAllLinks = false, withAllImages = false }) => {
    try {
      const urls = Array.isArray(url) ? [...new Set(url)] : [url];
      const settled = await Promise.allSettled(urls.map(u => readOne(u, { withAllLinks, withAllImages })));
      const content = settled.map((item, i) => item.status === "fulfilled"
        ? { type: "text", text: JSON.stringify(item.value, null, 2) }
        : { type: "text", text: JSON.stringify({ url: urls[i], error: String(item.reason?.message || item.reason) }, null, 2) });
      return { content, isError: settled.every(x => x.status === "rejected") };
    } catch (error) { return errorResult(error); }
  });

  server.registerTool("capture_screenshot", {
    title: "capture_screenshot",
    description: "Capture a first-screen or full-page screenshot using Jina Reader. The signed upstream URL is consumed server-side and is not exposed in text output.",
    inputSchema: { url: singleUrl, fullPage: z.boolean().default(false).optional(), fresh, viewport: viewportSchema }, annotations,
  }, async ({ url, fullPage = false, fresh = false, viewport }) => {
    try {
      const shot = await captureScreenshot(url, { fullPage, fresh, viewport });
      return { content: [{ type: "text", text: JSON.stringify(shot.metadata, null, 2) }, { type: "image", data: shot.data, mimeType: shot.mimeType }] };
    } catch (error) { return errorResult(error); }
  });

  server.registerTool("get_rendered_html", {
    title: "get_rendered_html",
    description: "Return sanitized Jina browser-rendered HTML, optionally narrowed to a CSS selector. Form values, srcdoc, event handlers, nonces and inline script bodies are redacted.",
    inputSchema: { url: singleUrl, selector: z.string().min(1).max(500).optional(), includeShadowDom: shadow, fresh, viewport: viewportSchema, maxChars: z.number().int().min(1000).max(500000).default(100000).optional() }, annotations,
  }, async ({ url, selector, includeShadowDom = true, fresh = false, viewport, maxChars = 100000 }) => {
    try {
      const page = await rendered(url, { selector, includeShadowDom, fresh, viewport });
      const safeHtml = sanitizeRenderedHtmlForOutput(page.html, { baseUrl: page.finalUrl });
      const truncated = safeHtml.length > maxChars;
      return textResult({ url: page.finalUrl, title: page.title, httpStatus: page.httpStatus, selector: selector || null, html: truncated ? safeHtml.slice(0, maxChars) : safeHtml, truncated, originalChars: safeHtml.length, sanitized: true });
    } catch (error) { return errorResult(error); }
  });

  server.registerTool("inspect_elements", {
    title: "inspect_elements",
    description: "Inspect selected elements in Jina's rendered HTML: safe attributes, bounded text, parent chain, and closest form. Does not claim live geometry or computed styles.",
    inputSchema: { url: singleUrl, selectors: z.array(z.string().min(1).max(300)).min(1).max(20), maxMatches: z.number().int().min(1).max(100).default(25).optional(), includeText: z.boolean().default(true).optional(), includeShadowDom: shadow, fresh }, annotations,
  }, async ({ url, selectors, maxMatches = 25, includeText = true, includeShadowDom = true, fresh = false }) => {
    try { const page = await rendered(url, { includeShadowDom, fresh }); return textResult({ url: page.finalUrl, title: page.title, ...inspectElements(page.html, { selectors, maxMatches, includeText, baseUrl: page.finalUrl }) }); }
    catch (error) { return errorResult(error); }
  });

  server.registerTool("inspect_dom", {
    title: "inspect_dom",
    description: "Summarize the rendered DOM structure with bounded tag counts, headings, landmarks, forms, controls, links, images, frames, scripts and stylesheet counts.",
    inputSchema: { url: singleUrl, includeShadowDom: shadow, fresh }, annotations,
  }, async ({ url, includeShadowDom = true, fresh = false }) => {
    try { const page = await rendered(url, { includeShadowDom, fresh }); return textResult({ url: page.finalUrl, title: page.title, ...inspectDom(page.html, { baseUrl: page.finalUrl }) }); }
    catch (error) { return errorResult(error); }
  });

  server.registerTool("inspect_frames", {
    title: "inspect_frames",
    description: "List iframe/frame element metadata from rendered HTML without claiming access to frame bodies. Anonymous Jina Reader does not permit iframe-content merging.",
    inputSchema: { url: singleUrl, maxFrames: z.number().int().min(1).max(100).default(50).optional(), includeShadowDom: shadow, fresh }, annotations,
  }, async ({ url, maxFrames = 50, includeShadowDom = true, fresh = false }) => {
    try { const page = await rendered(url, { includeShadowDom, fresh }); return textResult({ url: page.finalUrl, ...inspectFrames(page.html, { baseUrl: page.finalUrl, maxFrames }) }); }
    catch (error) { return errorResult(error); }
  });

  server.registerTool("inspect_styles", {
    title: "inspect_styles",
    description: "Inspect inline style sources, stylesheet links and selected inline style properties from rendered HTML. This is not browser CSSOM/computed-style output.",
    inputSchema: { url: singleUrl, selector: z.string().min(1).max(300).optional(), maxSheets: z.number().int().min(1).max(60).default(30).optional(), maxElements: z.number().int().min(1).max(80).default(30).optional(), includeShadowDom: shadow, fresh }, annotations,
  }, async ({ url, selector, maxSheets = 30, maxElements = 30, includeShadowDom = true, fresh = false }) => {
    try { const page = await rendered(url, { includeShadowDom, fresh }); return textResult({ url: page.finalUrl, ...inspectStyles(page.html, { baseUrl: page.finalUrl, selector, maxSheets, maxElements }) }); }
    catch (error) { return errorResult(error); }
  });

  server.registerTool("inspect_resources", {
    title: "inspect_resources",
    description: "Inventory scripts, links, images and media from rendered HTML. Inline script bodies are never returned; only length/hash metadata is exposed.",
    inputSchema: { url: singleUrl, maxPerType: z.number().int().min(1).max(150).default(80).optional(), includeShadowDom: shadow, fresh }, annotations,
  }, async ({ url, maxPerType = 80, includeShadowDom = true, fresh = false }) => {
    try { const page = await rendered(url, { includeShadowDom, fresh }); return textResult({ url: page.finalUrl, ...inspectResources(page.html, { baseUrl: page.finalUrl, maxPerType }) }); }
    catch (error) { return errorResult(error); }
  });

  server.registerTool("inspect_forms", {
    title: "inspect_forms",
    description: "Inventory forms and controls from rendered HTML while intentionally omitting input values, hidden values, textarea contents and option values.",
    inputSchema: { url: singleUrl, maxForms: z.number().int().min(1).max(50).default(30).optional(), maxControls: z.number().int().min(1).max(250).default(120).optional(), includeShadowDom: shadow, fresh }, annotations,
  }, async ({ url, maxForms = 30, maxControls = 120, includeShadowDom = true, fresh = false }) => {
    try { const page = await rendered(url, { includeShadowDom, fresh }); return textResult({ url: page.finalUrl, ...inspectForms(page.html, { baseUrl: page.finalUrl, maxForms, maxControls }) }); }
    catch (error) { return errorResult(error); }
  });

  server.registerTool("inspect_accessibility", {
    title: "inspect_accessibility",
    description: "Build a bounded HTML/ARIA semantic inventory for headings, links, buttons, controls, images and explicit roles. This is not Chromium's AX protocol tree.",
    inputSchema: { url: singleUrl, maxNodes: z.number().int().min(1).max(250).default(120).optional(), includeShadowDom: shadow, fresh }, annotations,
  }, async ({ url, maxNodes = 120, includeShadowDom = true, fresh = false }) => {
    try { const page = await rendered(url, { includeShadowDom, fresh }); return textResult({ url: page.finalUrl, ...inspectAccessibility(page.html, { maxNodes }) }); }
    catch (error) { return errorResult(error); }
  });

  server.registerTool("inspect_page_metadata", {
    title: "inspect_page_metadata",
    description: "Return rendered-page title, canonical URL, meta tags, HTML language/direction and Jina page metadata with structured URLs sanitized.",
    inputSchema: { url: singleUrl, includeShadowDom: shadow, fresh }, annotations,
  }, async ({ url, includeShadowDom = true, fresh = false }) => {
    try { const page = await rendered(url, { includeShadowDom, fresh }); return textResult(inspectPageMetadata(page.html, { baseUrl: page.finalUrl, jina: page })); }
    catch (error) { return errorResult(error); }
  });

  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  return { server, transport };
}
