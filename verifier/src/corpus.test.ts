// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { verifyBundle, type Bundle } from "./verify";
import { jsonTextProblem } from "./jsontext";

// The shared rejection corpus, the same file the Go suite reads
// (../../testdata/rejections.json, applied by corpus_test.go). Both
// implementations must refuse every case. An interop gate that only
// signs in one language and verifies in the other cannot catch the
// opposite failure, where one side accepts what the other refuses, and
// that is how offset timestamps, padded base64 and unsigned extra
// members all got in.
type Case = {
  name: string;
  why: string;
  /**
   * A fragment of the check name the refusal must mention. Every
   * mutation also breaks the signature, so without this a case passes
   * on the signature check while the rule it names goes untested.
   */
  expect?: string;
  path?: string;
  set?: unknown;
  delete?: boolean;
  // Raw cases mutate the serialized text, for properties a parse
  // destroys: duplicate members and lone surrogates.
  raw?: { duplicate?: string; injectString?: { find: string; replace: string } };
};

const corpus = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../testdata/rejections.json", import.meta.url)), "utf8"),
) as { cases: Case[] };

const fixture = JSON.parse(
  readFileSync(fileURLToPath(new URL("./testdata/sample-bundle.json", import.meta.url)), "utf8"),
) as { bundle: Bundle; body: string };

function apply(obj: Record<string, unknown>, c: Case): void {
  const path = (c.path ?? "").split(".");
  let cur: unknown = obj;
  for (let i = 0; i < path.length - 1; i++) {
    const seg = path[i];
    cur = Array.isArray(cur) ? cur[Number(seg)] : (cur as Record<string, unknown>)[seg];
    if (cur === undefined) throw new Error(`path ${c.path}: ${seg} is not in the fixture`);
  }
  const leaf = path[path.length - 1];
  const target = cur as Record<string, unknown>;
  if (c.delete) {
    delete target[leaf];
    return;
  }
  // "PADDED" means "this value, re-spelled with padding", which cannot
  // be written literally without hard-coding a signature.
  target[leaf] = c.set === "PADDED" ? `${String(target[leaf])}=` : c.set;
}

describe("shared rejection corpus", () => {
  it("has cases, and the unmutated fixture verifies", async () => {
    expect(corpus.cases.length).toBeGreaterThan(0);
    const res = await verifyBundle(fixture.bundle, fixture.body);
    expect(res.ok, "the fixture must verify or every case below passes for the wrong reason").toBe(true);
  });

  for (const c of corpus.cases) {
    it(`refuses: ${c.name}`, async () => {
      if (c.raw) {
        let text = JSON.stringify(fixture.bundle, null, 2);
        if (c.raw.duplicate) {
          const needle = `"${c.raw.duplicate}":`;
          const idx = text.indexOf(needle);
          expect(idx, `${c.raw.duplicate} is not in the fixture`).toBeGreaterThan(-1);
          text = text.slice(0, idx) + needle + ` "repeated",` + text.slice(idx);
        } else if (c.raw.injectString) {
          const { find, replace } = c.raw.injectString;
          expect(text.includes(find), `${find} is not in the fixture`).toBe(true);
          text = text.replace(find, replace);
        }
        expect(jsonTextProblem(text), c.why).not.toBeNull();
        return;
      }
      const b = JSON.parse(JSON.stringify(fixture.bundle)) as Record<string, unknown>;
      apply(b, c);
      const res = await verifyBundle(b);
      expect(res.ok, c.why).toBe(false);
      // Every case names the rule that must report it. A case without
      // one proves only that something refused the file, and every
      // mutation also breaks the signature, so that is no proof at all.
      expect(c.expect, `case "${c.name}" carries no expectation`).toBeTruthy();
      const failed = res.checks
        .filter((k) => !k.ok)
        .map((k) => `${k.name} ${k.detail ?? ""}`.toLowerCase());
      expect(
        failed.some((n) => n.includes(c.expect!.toLowerCase())),
        `refused, but not for the stated reason. Expected a failing check mentioning "${c.expect}", got: ${failed.join(" | ")}`,
      ).toBe(true);
    });
  }
});
