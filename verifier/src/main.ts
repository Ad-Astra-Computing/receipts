// SPDX-License-Identifier: Apache-2.0
import { verifyBundle, type Bundle } from "./verify";
import { renderReceipt } from "./render";
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

async function show(bundle: Bundle, body: string | undefined, animate: boolean) {
  const seq = ++renderSeq;
  const res = await verifyBundle(bundle, body);
  if (seq !== renderSeq) return; // a newer render superseded this one
  const c = card();
  c.classList.remove("animate");
  renderReceipt(inner(), bundle, body, res);
  if (animate && !reduceMotion()) {
    // Restart the CSS animation by forcing a reflow.
    void c.offsetWidth;
    c.classList.add("animate");
  }
}

function extract(data: unknown): { bundle: Bundle; body?: string } {
  const d = data as { bundle?: Bundle; body?: string } & Bundle;
  return { bundle: (d.bundle ?? d) as Bundle, body: d.body };
}

async function loadFile(f: File) {
  try {
    const { bundle, body } = extract(JSON.parse(await f.text()));
    await show(bundle, body, true);
    card().scrollIntoView({ behavior: reduceMotion() ? "auto" : "smooth", block: "center" });
  } catch (e) {
    inner().textContent = `Could not read that file: ${String(e)}`;
  }
}

function wire() {
  const input = document.getElementById("file") as HTMLInputElement | null;
  input?.addEventListener("change", () => {
    const f = input.files?.[0];
    if (f) void loadFile(f);
  });

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
    const f = e.dataTransfer?.files?.[0];
    if (f) void loadFile(f);
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
