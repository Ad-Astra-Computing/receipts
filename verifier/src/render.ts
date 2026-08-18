// SPDX-License-Identifier: Apache-2.0
// Renders a verified receipts bundle into the hero card. Pure DOM,
// textContent only (bundle content is untrusted). Animation is driven
// by an `animate` class the caller toggles; CSS owns the timing, so
// there is no fragile JS choreography and reduced-motion is a media
// query away.

import type { Bundle, VerifyResult } from "./verify";

const SVGNS = "http://www.w3.org/2000/svg";

function el(tag: string, cls?: string, text?: string): HTMLElement {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function safeHttp(url: string): string | null {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:" ? u.href : null;
  } catch {
    return null;
  }
}

// mergeRanges clamps every range to [0, bodyLen], drops empty/inverted
// ones, and merges overlaps into a sorted, non-overlapping cover. Both
// the percentage and the in-place highlighting build on this, so
// overlapping or out-of-bounds ranges can neither inflate the percent
// past 100 nor duplicate/reorder the displayed body.
/**
 * Converts UTF-8 byte offsets into JavaScript string indices.
 *
 * SPEC section 4: ai_ranges are byte offsets into the published body,
 * because a byte offset is the one position every language can agree on
 * without a table. JavaScript indexes strings in UTF-16 code units, so
 * the two only coincide for ASCII. An accented letter costs one extra
 * byte, an emoji three, and using the raw numbers moves the highlight
 * left by exactly that much: wrong words, marked confidently, and only
 * for text that is not plain English.
 *
 * Offsets that land inside a character (a corrupt or hostile bundle)
 * snap to the character boundary rather than splitting it.
 */
export function byteRangesToStringRanges(
  body: string,
  ranges: { from: number; to: number }[],
): { from: number; to: number }[] {
  if (ranges.length === 0) return [];
  // One walk over the body, recording the string index at each byte
  // boundary. byteToIndex[b] is the string index of the character that
  // starts at byte b.
  const byteToIndex = new Map<number, number>();
  let byteLen = 0;
  for (let i = 0; i < body.length; ) {
    byteToIndex.set(byteLen, i);
    const cp = body.codePointAt(i) as number;
    const width = cp > 0xffff ? 2 : 1; // surrogate pair or single unit
    byteLen += cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
    i += width;
  }
  byteToIndex.set(byteLen, body.length);

  const at = (byteOffset: number): number => {
    if (byteOffset <= 0) return 0;
    if (byteOffset >= byteLen) return body.length;
    const hit = byteToIndex.get(byteOffset);
    if (hit !== undefined) return hit;
    // Inside a character: snap forward to the next boundary.
    for (let b = byteOffset + 1; b <= byteLen; b++) {
      const next = byteToIndex.get(b);
      if (next !== undefined) return next;
    }
    return body.length;
  };

  return ranges.map((r) => {
    const from = at(r.from);
    const to = at(r.to);
    return { from, to: Math.max(from, to) };
  });
}

export function mergeRanges(
  ranges: { from: number; to: number }[],
  bodyLen: number,
): { from: number; to: number }[] {
  const clamped = ranges
    .map((r) => ({ from: Math.max(0, Math.min(r.from, bodyLen)), to: Math.max(0, Math.min(r.to, bodyLen)) }))
    .filter((r) => r.to > r.from)
    .sort((a, b) => a.from - b.from);
  const out: { from: number; to: number }[] = [];
  for (const r of clamped) {
    const last = out[out.length - 1];
    if (last && r.from <= last.to) last.to = Math.max(last.to, r.to);
    else out.push({ ...r });
  }
  return out;
}

// disclosedChars is the total body length covered by the merged ranges.
export function disclosedChars(ranges: { from: number; to: number }[], bodyLen: number): number {
  return mergeRanges(ranges, bodyLen).reduce((n, r) => n + (r.to - r.from), 0);
}

export function verdictSentence(bundle: Bundle, body: string | undefined, res: VerifyResult): string {
  if (!res.ok) {
    const failed = res.checks.filter((c) => !c.ok).map((c) => c.name.toLowerCase());
    return `Not verified. Problem with: ${failed.join(", ")}.`;
  }
  const cps = bundle.timeline.checkpoints ?? [];
  const words = cps.length ? cps[cps.length - 1].words : 0;
  let aiPct = 0;
  const ai = bundle.ai_ranges ?? [];
  if (body && ai.length) {
    // Convert first: these are byte offsets, and body.length is UTF-16
    // code units, so a non-ASCII body produced a wrong percentage.
    const inString = byteRangesToStringRanges(body, ai);
    aiPct = Math.round((disclosedChars(inString, body.length) / Math.max(1, body.length)) * 100);
  }
  const cpNote = cps.length ? `, ${words} words over ${cps.length} checkpoint${cps.length === 1 ? "" : "s"}` : "";
  // Only report a percentage when a body was present to compute it against.
  // An empty list is the common case and it used to say nothing at all,
  // which reads as "this was not checked" rather than "the author
  // disclosed none". Both halves are about disclosure, never about
  // whether AI was used: the receipt cannot know that.
  const aiNote = ai.length
    ? body !== undefined
      ? `, ${aiPct}% labeled AI-written`
      : ", with passages labeled AI-written"
    : ", no AI passages disclosed";
  // Only claim checks that actually ran. The text check runs only when
  // a body was supplied, so mention "bundled text" only if it did. The
  // C2PA credential is carried inside the signed receipt (its signature
  // value is bound) but re-verified in full by verifyBundle.
  const checked = ["the receipt's signature", "the content credential", "the timeline chain"];
  if (res.bodyChecked) {
    checked.push("the bundled text");
  }
  const list =
    checked.length > 1 ? `${checked.slice(0, -1).join(", ")} and ${checked[checked.length - 1]}` : checked[0];
  // Saying nothing about an absent body lets "verified" be read as "the
  // writing matches", which is a stronger statement than what ran.
  const bodyNote = res.bodyChecked
    ? ""
    : " The writing itself was not supplied, so it was not compared against this receipt.";
  return `Verified. ${list[0].toUpperCase()}${list.slice(1)} check out${cpNote}${aiNote}.${bodyNote}`;
}

function curve(bundle: Bundle): HTMLElement {
  const cps = bundle.timeline.checkpoints ?? [];
  const fig = el("figure", "curve");
  const svg = document.createElementNS(SVGNS, "svg");
  svg.setAttribute("viewBox", "0 0 100 100");
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("role", "img");
  const words = cps.length ? cps[cps.length - 1].words : 0;
  svg.setAttribute("aria-label", `Composition curve: ${cps.length} checkpoints ending at ${words} words.`);
  if (cps.length >= 2) {
    const maxW = Math.max(1, ...cps.map((c) => c.words));
    const pts = cps.map((c, i) => ({
      x: (i / (cps.length - 1)) * 100,
      y: 100 - (c.words / maxW) * 78 - 10,
    }));
    const line = pts.map((p, i) => `${i === 0 ? "M" : "L"}${p.x.toFixed(2)},${p.y.toFixed(2)}`).join(" ");

    // Filled area under the line grounds the plot: a two-checkpoint
    // sample would otherwise read as a lone diagonal streak.
    const area = document.createElementNS(SVGNS, "path");
    area.setAttribute("d", `${line} L100,100 L0,100 Z`);
    area.setAttribute("class", "curve-fill");
    svg.append(area);

    const path = document.createElementNS(SVGNS, "path");
    path.setAttribute("d", line);
    path.setAttribute("pathLength", "1"); // normalize so dash draw works for any curve
    path.setAttribute("class", "curve-path");
    path.setAttribute("fill", "none");
    path.setAttribute("stroke-width", "2");
    path.setAttribute("stroke-linejoin", "round");
    path.setAttribute("stroke-linecap", "round");
    path.setAttribute("vector-effect", "non-scaling-stroke");
    svg.append(path);
  }
  fig.append(svg);

  // A short caption so the reader knows what the plot is.
  const label = el(
    "figcaption",
    "curve-label",
    `Composition · ${words} words over ${cps.length} checkpoint${cps.length === 1 ? "" : "s"}`,
  );
  fig.append(label);

  // Visually-hidden table equivalent for screen readers.
  const table = el("table", "visually-hidden");
  const cap = el("caption", undefined, "Composition checkpoints");
  table.append(cap);
  const thead = el("thead");
  const htr = el("tr");
  for (const h of ["Checkpoint", "Words"]) {
    const th = el("th", undefined, h);
    th.setAttribute("scope", "col");
    htr.append(th);
  }
  thead.append(htr);
  table.append(thead);
  const tb = el("tbody");
  cps.forEach((c, i) => {
    const tr = el("tr");
    tr.append(el("td", undefined, String(i + 1)));
    tr.append(el("td", undefined, String(c.words)));
    tb.append(tr);
  });
  table.append(tb);
  fig.append(table);
  return fig;
}

// stripFrontmatter removes a leading TOML/YAML frontmatter block so the
// receipt shows the prose a reader actually sees, not raw `+++ ... +++`.
// Returns the byte offset removed so range offsets (which index the full
// body) can be shifted onto the prose.
export function stripFrontmatter(body: string): { prose: string; offset: number } {
  const m = /^(\+\+\+|---)\r?\n[\s\S]*?\r?\n\1\r?\n+/.exec(body);
  if (m) return { prose: body.slice(m[0].length), offset: m[0].length };
  return { prose: body, offset: 0 };
}

// excerptProse trims the prose to a readable excerpt that always ends on
// a whole word. It keeps at least `minEnd` characters (so the last
// AI-marked range is fully shown) plus trailing context. If the natural
// end of the prose is within reach it shows the whole thing and reports
// no ellipsis; otherwise it backs up to the previous word boundary and
// reports an ellipsis so the reader knows more follows.
export function excerptProse(prose: string, minEnd: number): { text: string; ellipsis: boolean } {
  const trimmed = prose.replace(/\s+$/, "");
  const target = minEnd + 80;
  // If the whole prose is within reach of the target, show it complete
  // rather than truncating a sentence that almost fits.
  if (target + 60 >= trimmed.length) return { text: trimmed, ellipsis: false };
  // Back up from the target to the last whitespace so we never split a word.
  let end = target;
  while (end > minEnd && !/\s/.test(trimmed[end])) end--;
  while (end > minEnd && /\s/.test(trimmed[end - 1])) end--;
  return { text: trimmed.slice(0, end), ellipsis: true };
}

function tapeBody(body: string, ranges: { from: number; to: number }[], ellipsis = false): HTMLElement {
  const wrap = el("div", "tape-body");
  // Merged, non-overlapping, clamped intervals: cursor only advances,
  // so the concatenation of rendered text is exactly the body.
  const merged = mergeRanges(ranges, body.length);
  let cursor = 0;
  for (const r of merged) {
    if (r.from > cursor) wrap.append(document.createTextNode(body.slice(cursor, r.from)));
    const mark = el("mark", "ai");
    mark.textContent = body.slice(r.from, r.to);
    mark.title = "labeled AI-written";
    wrap.append(mark);
    cursor = r.to;
  }
  if (cursor < body.length) wrap.append(document.createTextNode(body.slice(cursor)));
  if (ellipsis) wrap.append(document.createTextNode("…"));
  return wrap;
}

/** Whether the shape this renderer reads is actually present. */
function isRenderable(b: unknown): b is Bundle {
  if (typeof b !== "object" || b === null) return false;
  const o = b as Record<string, unknown>;
  const post = o.post as Record<string, unknown> | undefined;
  const timeline = o.timeline as Record<string, unknown> | undefined;
  return (
    typeof post === "object" && post !== null &&
    typeof timeline === "object" && timeline !== null &&
    Array.isArray(timeline.checkpoints)
  );
}

export function renderReceipt(inner: HTMLElement, bundle: Bundle, body: string | undefined, res: VerifyResult) {
  inner.replaceChildren(); // DOM/text-only: never innerHTML with bundle content
  inner.classList.toggle("failed", !res.ok);

  // verifyBundle is total over any input, but this is not: it reads
  // bundle.post.title and bundle.timeline directly, so a document that
  // failed the structural checks would throw here and break the page,
  // which is the outcome making verification total was meant to prevent.
  // A document that is not shaped like a receipt has nothing to render
  // beyond why it was refused.
  if (!isRenderable(bundle)) {
    const head = el("div", "r-head");
    head.append(el("div", "r-title", "Not a receipt"));
    inner.append(head);
    for (const c of res.checks.filter((c) => !c.ok)) {
      inner.append(el("div", "r-check fail", `${c.name}: ${c.detail ?? "failed"}`));
    }
    return;
  }

  // Title + fingerprint (ledger header)
  const head = el("div", "r-head");
  head.append(el("div", "r-title", bundle.post.title || "Untitled"));
  head.append(el("div", "r-key", `signed ${res.fingerprint || "unknown"}`));
  inner.append(head);

  // Checks
  const ol = el("ol", "r-checks");
  for (const c of res.checks) {
    const li = el("li", `r-check ${c.ok ? "ok" : "bad"}`);
    li.append(el("span", "r-glyph", c.ok ? "✓" : "✕"));
    li.append(el("span", "r-name", c.name));
    ol.append(li);
  }
  inner.append(ol);

  // Verdict (announced)
  const verdict = el("p", `r-verdict ${res.ok ? "good" : "bad"}`);
  verdict.setAttribute("role", "status");
  verdict.setAttribute("aria-live", "polite");
  verdict.textContent = verdictSentence(bundle, body, res);
  inner.append(verdict);

  // Curve
  if ((bundle.timeline.checkpoints ?? []).length > 0) inner.append(curve(bundle));

  // Tape body excerpt (only when body available and AI ranges exist).
  // Strip frontmatter and shift the ranges onto the prose so the reader
  // sees the words, not the raw +++ header.
  const ai = bundle.ai_ranges ?? [];
  if (body !== undefined && ai.length > 0) {
    const { prose, offset } = stripFrontmatter(body);
    // Byte offsets first, against the whole body; `offset` is a string
    // index into it, so subtracting it from bytes mixed two different
    // units and shifted the marks twice over.
    const inString = byteRangesToStringRanges(body, ai);
    const shifted = inString.map((r) => ({ from: r.from - offset, to: r.to - offset }));
    const { text, ellipsis } = excerptProse(prose, Math.max(0, ...shifted.map((r) => r.to)));
    inner.append(tapeBody(text, shifted, ellipsis));
  }

  // Claims
  const claims = bundle.claims ?? [];
  if (claims.length > 0) {
    const ul = el("ul", "r-claims");
    for (const c of claims) {
      const li = el("li");
      li.append(el("span", "r-claim-x", c.excerpt));
      const href = safeHttp(c.source_url);
      if (href) {
        const a = el("a", "r-claim-src") as HTMLAnchorElement;
        a.href = href;
        a.textContent = new URL(href).hostname;
        // noopener already denies the opened page window.opener; noreferrer
        // also withholds the Referer, so following a claim's source does not
        // tell that site the reader was verifying a receipt.
        a.rel = "noopener noreferrer";
        a.target = "_blank";
        // The receipt card is a <label> for the file input; keep a link
        // click from also opening the file picker.
        a.addEventListener("click", (e) => e.stopPropagation());
        li.append(a);
      }
      ul.append(li);
    }
    inner.append(ul);
  }
}
