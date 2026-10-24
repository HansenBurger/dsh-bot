// Verify every ```mermaid block in the given Markdown files parses.
// Usage: node scripts/check-mermaid.mjs <file.md> [...more]
// Rationale: `mmdc` needs chrome-headless-shell which is unavailable here, so we call
// mermaid's own parser directly under a jsdom window (same approach as t2).
import { JSDOM } from 'jsdom';
import fs from 'node:fs';

const dom = new JSDOM('<!DOCTYPE html><body></body>', { pretendToBeVisual: true });
globalThis.window = dom.window;
globalThis.document = dom.window.document;
Object.defineProperty(globalThis, 'navigator', {
  value: dom.window.navigator,
  configurable: true,
  writable: true,
});
globalThis.HTMLElement = dom.window.HTMLElement;
globalThis.Element = dom.window.Element;
globalThis.SVGElement = dom.window.SVGElement;
globalThis.Node = dom.window.Node;
globalThis.getComputedStyle = dom.window.getComputedStyle.bind(dom.window);
globalThis.MutationObserver = dom.window.MutationObserver;
globalThis.requestAnimationFrame = (cb) => setTimeout(cb, 0);
globalThis.cancelAnimationFrame = (id) => clearTimeout(id);

const mermaid = (await import('mermaid')).default;
mermaid.initialize({ startOnLoad: false, securityLevel: 'loose' });

let failed = 0;
let checked = 0;
for (const file of process.argv.slice(2)) {
  const src = fs.readFileSync(file, 'utf8');
  const blocks = [...src.matchAll(/```mermaid\r?\n([\s\S]*?)```/g)].map((m) => m[1]);
  console.log(`# ${file}: ${blocks.length} mermaid block(s)`);
  for (const [i, body] of blocks.entries()) {
    checked++;
    try {
      await mermaid.parse(body);
      console.log(`  block ${i + 1}: PARSE OK`);
    } catch (err) {
      failed++;
      const detail = String(err && err.message ? err.message : err).split('\n').slice(0, 5).join(' | ');
      console.log(`  block ${i + 1}: PARSE FAIL -> ${detail}`);
    }
  }
}
console.log(`checked=${checked} failed=${failed}`);
process.exit(failed ? 1 : 0);
