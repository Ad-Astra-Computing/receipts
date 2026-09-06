import { describe, it, expect } from "vitest";
import { stampSitemap } from "../scripts/stamp-sitemap.mjs";

const SITEMAP = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/</loc>
    <lastmod>1999-01-01</lastmod>
  </url>
  <url>
    <loc>https://example.com/privacy</loc>
    <lastmod>2026-08-20</lastmod>
  </url>
</urlset>`;

const PAGES = {
  "https://example.com/": "index.html",
  "https://example.com/privacy": "public/privacy.html",
};

const dates = () => ({
  "index.html": "2026-08-20",
  "public/privacy.html": "2026-08-20",
});

describe("stampSitemap", () => {
  it("writes the commit date into each entry", () => {
    const { xml } = stampSitemap(SITEMAP, PAGES, (f) => dates()[f]);
    expect(xml).toContain("<lastmod>2026-08-20</lastmod>");
    expect(xml).not.toContain("1999-01-01");
  });

  it("counts an entry it dated even when the date was already right", () => {
    // The whole point is proving the sitemap is managed. Counting only
    // changes makes a correct build indistinguishable from a broken one.
    const { dated } = stampSitemap(SITEMAP, PAGES, (f) => dates()[f]);
    expect(dated).toBe(2);
  });

  it("reports a page whose URL is not in the sitemap", () => {
    const pages = { ...PAGES, "https://example.com/gone": "public/gone.html" };
    const { unmatched } = stampSitemap(SITEMAP, pages, () => "2026-08-20");
    expect(unmatched).toEqual(["https://example.com/gone"]);
  });

  it("leaves a date alone when git cannot answer", () => {
    const { xml, dated } = stampSitemap(SITEMAP, PAGES, () => null);
    expect(xml).toContain("1999-01-01");
    expect(dated).toBe(0);
  });

  it("does not let one url's pattern match another entry", () => {
    // "https://example.com/" is a prefix of every other URL, so a loose
    // pattern would stamp the wrong row.
    const { xml } = stampSitemap(SITEMAP, { "https://example.com/": "index.html" }, () => "2020-02-02");
    expect(xml).toContain("<loc>https://example.com/privacy</loc>\n    <lastmod>2026-08-20</lastmod>");
  });
});
