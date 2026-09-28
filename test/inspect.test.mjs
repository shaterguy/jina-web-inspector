import test from "node:test";
import assert from "node:assert/strict";
import { assertPublicHttpUrl, sanitizeUrl } from "../src/jina.mjs";
import { inspectElements, inspectForms, inspectResources, inspectAccessibility, inspectStyles } from "../src/inspect.mjs";

const html = `<!doctype html><html lang="en"><head><title>T</title><style>.x{display:none;background:url('https://cdn.example/a.png?token=secret')}</style><script>window.SECRET='do-not-return'</script><script src="https://cdn.example/app.js?key=abc"></script></head><body><main><h1 id="title">Hello</h1><form id="login" action="https://example.com/login?session=abc" method="post"><label for="pw">Password</label><input id="pw" name="password" type="password" value="super-secret" autocomplete="current-password" style="display:none;position:absolute;color:red"><button type="submit">Go</button></form><iframe src="https://frame.example/path?token=x"></iframe><a href="https://example.com/x?auth=abc#frag">Link</a></main></body></html>`;

test("URL safety rejects loopback/private literal addresses", () => {
  assert.throws(() => assertPublicHttpUrl("http://127.0.0.1/x"));
  assert.throws(() => assertPublicHttpUrl("http://192.168.1.2/x"));
  assert.equal(assertPublicHttpUrl("https://example.com/a"), "https://example.com/a");
});

test("sanitizeUrl removes credentials/query/fragment", () => {
  assert.equal(sanitizeUrl("https://u:p@example.com/a?token=x#z"), "https://example.com/a");
});

test("element/form inspection never returns control values", () => {
  const elements = inspectElements(html, { selectors: ["input", "button"], baseUrl: "https://example.com/", maxMatches: 10 });
  const serialized = JSON.stringify(elements);
  assert.equal(serialized.includes("super-secret"), false);
  assert.equal(serialized.includes('"value"'), false);
  assert.equal(elements.results[0].matches[0].attrs.inlineStyle.display, "none");
  const forms = inspectForms(html, { baseUrl: "https://example.com/" });
  const f = JSON.stringify(forms);
  assert.equal(f.includes("super-secret"), false);
  assert.equal(forms.forms[0].action, "https://example.com/login");
});

test("resource inspection hashes inline scripts and sanitizes external URLs", () => {
  const r = inspectResources(html, { baseUrl: "https://example.com/" });
  const s = JSON.stringify(r);
  assert.equal(s.includes("do-not-return"), false);
  assert.equal(r.scripts[0].inlineLength > 0, true);
  assert.equal(r.scripts[1].src, "https://cdn.example/app.js");
});

test("accessibility inventory derives safe labels", () => {
  const a = inspectAccessibility(html, { maxNodes: 20 });
  const pw = a.nodes.find(x => x.id === "pw");
  assert.equal(pw.label, "Password");
  assert.equal(JSON.stringify(a).includes("super-secret"), false);
});

test("style inspection redacts URL query values from snippets", () => {
  const s = inspectStyles(html, { baseUrl: "https://example.com/" });
  assert.equal(s.inlineStylesheets[0].snippet.includes("token=secret"), false);
  assert.equal(s.inlineStylesheets[0].snippet.includes("https://cdn.example/a.png"), true);
});
