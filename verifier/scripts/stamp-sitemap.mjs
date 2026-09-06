// Stamp each sitemap entry's <lastmod> with the date its page was last
// committed.
//
// A hand-maintained date drifts the moment somebody edits a page and
// forgets, and a sitemap that lies about freshness is worse than one
// that says nothing: crawlers learn to distrust it. Git already knows
// when each file changed, so the build asks git rather than a human.
//
// Runs against dist/ after vite has copied public/ across, so the source
// file stays whatever git says and only the built output is stamped.

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

function lastCommitDate(file) {
  try {
    const out = execFileSync(
      "git",
      ["log", "-1", "--format=%ad", "--date=short", "--", file],
      { encoding: "utf8" },
    ).trim();
    return out || null;
  } catch {
    // A shallow clone or an export with no git history is not a build
    // failure; the existing dates simply stand.
    return null;
  }
}

// stampSitemap returns the rewritten xml, how many entries it dated, and
// any configured page it could not find.
//
// `dated` counts entries matched, not entries changed. Counting changes
// made a correct rebuild report "0 of 3", which read exactly like a
// pattern that had silently stopped matching.
export function stampSitemap(xml, pages, commitDate) {
  let dated = 0;
  const unmatched = [];

  for (const [url, file] of Object.entries(pages)) {
    const quoted = url.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    // Anchored on the closing </loc> so that "/" does not match the row
    // belonging to "/privacy".
    const pattern = new RegExp(
      `(<loc>${quoted}</loc>\\s*<lastmod>)[^<]*(</lastmod>)`,
    );
    if (!pattern.test(xml)) {
      unmatched.push(url);
      continue;
    }
    const date = commitDate(file);
    if (!date) continue;
    xml = xml.replace(pattern, `$1${date}$2`);
    dated++;
  }
  return { xml, dated, unmatched };
}

// Only run as a script, not when imported by a test.
if (process.argv[1] && process.argv[1].endsWith("stamp-sitemap.mjs")) {
  if (!existsSync(SITEMAP)) {
    console.error(`stamp-sitemap: no ${SITEMAP}; run after vite build`);
    process.exit(1);
  }
  const { xml, dated, unmatched } = stampSitemap(
    readFileSync(SITEMAP, "utf8"),
    PAGES,
    lastCommitDate,
  );
  if (unmatched.length) {
    console.error(
      `stamp-sitemap: ${unmatched.join(", ")} is configured here but absent from ${SITEMAP}`,
    );
    process.exit(1);
  }
  writeFileSync(SITEMAP, xml);
  console.log(
    `stamp-sitemap: dated ${dated} of ${Object.keys(PAGES).length} entries from git`,
  );
}
