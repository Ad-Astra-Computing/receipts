// Stamp each sitemap entry's <lastmod> with the date its page was last
// committed.
//
// A hand-maintained date drifts the moment somebody edits a page and
// forgets, and a sitemap that lies about freshness is worse than one
// that says nothing: crawlers learn to distrust it. Git already knows
// when each file changed, so the build asks git rather than a human.
//
// Runs against dist/ after vite has copied public/ across, so the
// source file stays whatever git says and only the built output is
// stamped.

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync } from "node:fs";

const SITEMAP = "dist/sitemap.xml";

// Which source file backs each URL. A page absent from here keeps
// whatever date the source sitemap carries.
const PAGES = {
  "https://receiptsofthought.com/": "index.html",
  "https://receiptsofthought.com/privacy": "public/privacy.html",
  "https://receiptsofthought.com/terms": "public/terms.html",
};

if (!existsSync(SITEMAP)) {
  console.error(`stamp-sitemap: no ${SITEMAP}; run after vite build`);
  process.exit(1);
}

function lastCommitDate(file) {
  try {
    const out = execFileSync("git", ["log", "-1", "--format=%ad", "--date=short", "--", file], {
      encoding: "utf8",
    }).trim();
    return out || null;
  } catch {
    // A shallow clone or an export with no git history is not a build
    // failure; the existing dates simply stand.
    return null;
  }
}

let xml = readFileSync(SITEMAP, "utf8");
let stamped = 0;

for (const [url, file] of Object.entries(PAGES)) {
  const date = lastCommitDate(file);
  if (!date) continue;
  const pattern = new RegExp(
    `(<loc>${url.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}</loc>\\s*<lastmod>)[^<]*(</lastmod>)`,
  );
  const next = xml.replace(pattern, `$1${date}$2`);
  if (next !== xml) {
    xml = next;
    stamped++;
  }
}

writeFileSync(SITEMAP, xml);
console.log(`stamp-sitemap: dated ${stamped} of ${Object.keys(PAGES).length} entries from git`);
