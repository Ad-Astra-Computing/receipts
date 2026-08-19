// SPDX-License-Identifier: Apache-2.0
import { verifyBundle, type Bundle } from "./verify";
import { renderReceipt } from "./render";
import { jsonTextProblem } from "./jsontext";
import { tamper, type Tamper } from "./tamper";
// The hero sample is bundled in, not fetched, so it is instant and
// cannot fail at the edge. Swap this file to change the demo receipt.
import sampleData from "./sample.receipts.json";

const inner = () => document.getElementById("receipt-inner")!;
const card = () => document.getElementById("receipt-card")!;

const reduceMotion = () =>
  typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;

// Monotonic token so a slow render can't overwrite a newer one (e.g.
// the hero's async verify landing after a user has dropped a file).
let renderSeq = 0;

async function show(
  bundle: Bundle,
  body: string | undefined,
  animate: boolean,
  label?: string,
  changed?: string,
) {
  const seq = ++renderSeq;
  if (label) {
    inner().setAttribute("aria-busy", "true");
    inner().textContent = `Checking ${label}…`;
  }
  const res = await verifyBundle(bundle, body);
  inner().setAttribute("aria-busy", "false");
  if (seq !== renderSeq) return; // a newer render superseded this one
  const c = card();
  c.classList.remove("animate");
  renderReceipt(inner(), bundle, body, res, changed);
  if (animate && !reduceMotion()) {
    // Restart the CSS animation by forcing a reflow.
    void c.offsetWidth;
    c.classList.add("animate");
  }
}

/**
 * Reads a receipts file: either a bare bundle or the transport envelope
 * of SPEC 3a. Strict about the envelope, as receipts.Decode is in Go:
 * a document with a `bundle` member is an envelope and may hold nothing
 * but `bundle` and `body`, and `body` must be text. Being lax here while
 * the library is strict means the same file is read two ways.
 */
function extract(data: unknown): { bundle: Bundle; body?: string; problem?: string } {
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    return { bundle: data as Bundle, problem: "this file is not a JSON object" };
  }
  const d = data as Record<string, unknown>;
  if (!("bundle" in d)) return { bundle: data as Bundle };

  const extra = Object.keys(d).filter((k) => k !== "bundle" && k !== "body");
  if (extra.length > 0) {
    return { bundle: d.bundle as Bundle, problem: `this envelope has unexpected members: ${extra.join(", ")}` };
  }
  if ("body" in d && typeof d.body !== "string") {
    return { bundle: d.bundle as Bundle, problem: "this envelope's body is not text" };
  }
  return { bundle: d.bundle as Bundle, body: d.body as string | undefined };
}

async function loadFile(f: File) {
  card().classList.add("has-file");
  try {
    // Not f.text(): that replaces invalid UTF-8 with U+FFFD, so a file
    // Go refuses as malformed would be silently repaired here and then
    // validated in its repaired form.
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(await f.arrayBuffer());
    } catch {
      inner().setAttribute("aria-busy", "false");
      inner().textContent = `${f.name} is not valid UTF-8 text, so it cannot be a receipt.`;
      return;
    }
    // Duplicate members and lone surrogates are properties of the text,
    // and JSON.parse destroys the evidence of both.
    const textProblem = jsonTextProblem(text);
    if (textProblem) {
      inner().setAttribute("aria-busy", "false");
      inner().textContent = `${f.name} cannot be checked: ${textProblem}.`;
      return;
    }
    const { bundle, body, problem } = extract(JSON.parse(text));
    if (problem) {
      inner().setAttribute("aria-busy", "false");
      inner().textContent = `${f.name} cannot be checked: ${problem}.`;
      return;
    }
    await show(bundle, body, true, f.name);
    card().scrollIntoView({ behavior: reduceMotion() ? "auto" : "smooth", block: "center" });
  } catch {
    // The exception text names a byte offset in a file the reader cannot
    // see. What they need is what to do next.
    inner().setAttribute("aria-busy", "false");
    inner().textContent =
      `${f.name} is not a receipt this page can read. A receipt is a .receipts.json file, published beside the writing it describes.`;
  }
}

/** Loads exactly one file, and says so when several arrive. */
function loadOne(files: FileList | null | undefined) {
  const list = files ? Array.from(files) : [];
  if (list.length === 0) return;
  if (list.length > 1) {
    card().classList.add("has-file");
    inner().setAttribute("aria-busy", "false");
    inner().textContent = `Drop one receipt at a time. ${list.length} files arrived together.`;
    return;
  }
  void loadFile(list[0]);
}

function wire() {
  const input = document.getElementById("file") as HTMLInputElement | null;
  input?.addEventListener("change", () => loadOne(input.files));

  // Whole-window drag target so a drop anywhere works.
  let dragDepth = 0;
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("dragenter", (e) => {
    e.preventDefault();
    dragDepth++;
    card().classList.add("over");
  });
  window.addEventListener("dragleave", () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) card().classList.remove("over");
  });
  window.addEventListener("drop", (e) => {
    e.preventDefault();
    dragDepth = 0;
    card().classList.remove("over");
    loadOne(e.dataTransfer?.files);
  });
}

/**
 * The tamper controls. The page claims that changing a receipt after
 * signing is detectable, and a reader has no reason to take that on
 * trust, so the buttons make the changes a forger would make and let the
 * real verifier refuse them here.
 */
function wireTamper(bundle: Bundle, body: string | undefined): void {
  const panel = document.getElementById("tamper");
  if (!panel) return;
  panel.hidden = false;
  const reset = panel.querySelector<HTMLButtonElement>(".tamper-reset");
  const note = () => document.getElementById("tamper-note");

  // Show the edit, not just its effect. A demonstration that hides what
  // it changed is asking for the trust it claims to replace.
  const setNote = (t: { note: string; before: string; after: string } | null) => {
    let el = note();
    if (!t) {
      el?.remove();
      return;
    }
    if (!el) {
      el = document.createElement("p");
      el.id = "tamper-note";
      el.className = "tamper-note";
      el.setAttribute("role", "status");
      panel.after(el);
    }
    el.replaceChildren();
    el.append(document.createTextNode(`${t.note} `));
    if (t.before || t.after) {
      const change = document.createElement("span");
      change.className = "tamper-change";
      const was = document.createElement("del");
      was.textContent = t.before;
      const now = document.createElement("ins");
      now.textContent = t.after;
      change.append(was, document.createTextNode(" \u2192 "), now);
      el.append(change, document.createTextNode(" "));
    }
    el.append(document.createTextNode("The receipt no longer verifies."));
  };

  panel.addEventListener("click", (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLButtonElement>("[data-tamper]");
    if (!btn) return;
    const kind = btn.dataset.tamper as Tamper | "reset";
    if (kind === "reset") {
      if (reset) reset.hidden = true;
      setNote(null);
      card().classList.remove("has-file");
      void show(bundle, body, true);
      return;
    }
    const t = tamper(kind, bundle, body);
    if (reset) reset.hidden = false;
    setNote(t);
    card().classList.add("has-file"); // it is no longer the pristine demo
    // Pass the new wording so the receipt marks it: the reader should
    // see what changed on the receipt, not only read about it below.
    void show(t.bundle, t.body, true, undefined, kind === "body" ? t.after : undefined);
  });
}

function main() {
  wire();
  // Auto-verify the bundled sample receipt as the hero.
  const { bundle, body } = extract(sampleData);
  let painted = false;
  const paint = (animate: boolean) => {
    if (painted) return;
    painted = true;
    void show(bundle, body, animate);
  };
  wireTamper(bundle, body);
  // Animate when the hero scrolls into view. Feature-detect first:
  // constructing IntersectionObserver where it is unavailable would
  // throw and leave the hero unpainted.
  if ("IntersectionObserver" in window) {
    const io = new IntersectionObserver(
      (entries, obs) => {
        if (entries.some((en) => en.isIntersecting)) {
          paint(true);
          obs.disconnect();
        }
      },
      { threshold: 0.25 },
    );
    io.observe(card());
    // Safety net if the observer never fires.
    setTimeout(() => paint(false), 1500);
  } else {
    paint(true);
  }
}

main();
