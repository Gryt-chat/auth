/**
 * Asserts every class gryt.css styles is still in the CSS the build emits.
 *
 * The lint config next door explains the bug this pair exists for: a rule
 * missing its closing brace nested the rest of the file inside a `::marker`,
 * and the bundler dropped 245 lines without saying anything. stylelint catches
 * that one, because an unclosed block is a syntax error.
 *
 * This catches the same *outcome* from a cause that is not a syntax error —
 * a mis-typed media query, a nesting mistake that parses fine, a bundler
 * upgrade that changes what survives. Those all look like the build working.
 *
 * It maintains itself: the expected list is read out of the source every run,
 * so deleting a rule on purpose needs nothing done here.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const sourcePath = join(root, "src/login/gryt.css");
const assets = join(root, "dist/assets");

const source = readFileSync(sourcePath, "utf8")
  // Class names are quoted in comments here often enough to matter, and a
  // commented-out rule is not one the bundle owes us.
  .replace(/\/\*[\s\S]*?\*\//g, "");

// Selector position only: the left of a `{`, never inside a declaration, so
// `[class*="gryt-"]` in a :not() and url()s in values stay out of it.
const wanted = new Set();
for (const block of source.matchAll(/(^|})([^{}]*)\{/g)) {
  for (const cls of block[2].matchAll(/\.([A-Za-z][\w-]*)/g)) wanted.add(cls[1]);
}

if (wanted.size === 0) {
  console.error(`check-built-css: found no class selectors in ${sourcePath}.`);
  console.error("check-built-css: that is the check itself being broken, not the CSS.");
  process.exit(1);
}

const built = readdirSync(assets).filter((f) => f.startsWith("KcPage-") && f.endsWith(".css"));
if (built.length !== 1) {
  console.error(`check-built-css: expected one KcPage-*.css in ${assets}, found ${built.length}.`);
  console.error("check-built-css: run `npm run build` first; a stale dist/ gives a stale answer.");
  process.exit(1);
}

const bundle = readFileSync(join(assets, built[0]), "utf8");
const missing = [...wanted].filter((cls) => !bundle.includes(`.${cls}`)).sort();

if (missing.length > 0) {
  console.error(`check-built-css: ${missing.length} class(es) styled in gryt.css are absent from ${built[0]}:`);
  for (const cls of missing) console.error(`  .${cls}`);
  console.error("");
  console.error("check-built-css: the build dropped these silently. Usually a rule above the");
  console.error("first one listed is malformed and swallowed what follows it.");
  process.exit(1);
}

console.log(`check-built-css: ${wanted.size} classes, all present in ${built[0]}.`);
