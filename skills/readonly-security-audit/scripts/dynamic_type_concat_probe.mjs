#!/usr/bin/env node
// dynamic_type_concat_probe.mjs — find message builders that splice caller strings into
// variable-length EIP-712 fields (`bytes`, not `bytes32`) with no length check.
// See references/signature-binding-sign-vs-execute.md §5f.
//
// RUN FROM THE REPO ROOT (viem/SDK resolve from ./node_modules) — §7b rule 1.
//   node dynamic_type_concat_probe.mjs <repo-root> [sdk-dist-glob]
//
// Stage 1 (static, always): scan the target's own src/ + the SDK dist for string
// concatenation into fields that are typed `bytes`/`bytes[]` in an EIP-712 struct, and
// for `.slice(2)` / `.substr(2)` on address-like values (the tell that the code ASSUMES
// a 20-byte input without enforcing it).
// Stage 2 (optional, --exec <module> <fn>): import the REAL exported builder and show
// that a padded input changes the field length — the §5f proof shape.
//
// Never assert on a decode branch you have not printed the intermediate values for.

import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import path from "node:path";

const args = process.argv.slice(2);
const repoRoot = path.resolve(args[0] ?? ".");
const sdkGlob = args[1] ?? "node_modules/*/dist";
const execIdx = args.indexOf("--exec");

const run = (cmd, argv) => {
  try {
    return execFileSync(cmd, argv, { cwd: repoRoot, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  } catch (e) {
    return e.stdout ?? "";
  }
};

// ---------------------------------------------------------------- stage 1: static
// Concatenation assigned to a field name that commonly carries dynamic types.
const CONCAT_RE = /\b(data|id|nonce|extraData|payload|blob|bytes|salt)\s*:\s*[^,;\n]*\+/;
// Address-slicing on a caller-supplied value: assumes 20 bytes, enforces nothing.
const SLICE_RE = /\.(slice|substr|substring)\(\s*2\s*\)/;
const CONCAT_HEX_RE = /\$\{[^}]*(depositor|recipient|owner|wallet|address|user)[^}]*\}/i;

const scanFile = (rel) => {
  const src = run("cat", [rel]);
  const hits = [];
  src.split("\n").forEach((line, i) => {
    const n = i + 1;
    if (CONCAT_RE.test(line) || CONCAT_HEX_RE.test(line) || SLICE_RE.test(line)) {
      hits.push({ file: rel, line: n, text: line.trim().slice(0, 160) });
    }
  });
  return hits;
};

const listFiles = (dir) =>
  run("sh", ["-c", `find ${dir} -type f \\( -name '*.js' -o -name '*.ts' \\) 2>/dev/null | grep -v '\\.d\\.ts$' | head -400`])
    .split("\n")
    .filter(Boolean);

console.log(`repo: ${repoRoot}`);
let all = [];
for (const dir of ["src", sdkGlob]) {
  for (const f of listFiles(dir)) all = all.concat(scanFile(f));
}

// Rank: a concat into `data`/`extraData` (true dynamic type) beats a bare address slice.
const score = (h) => (/data|payload|blob/i.test(h.text) ? 3 : 1) + (/\+/.test(h.text) ? 2 : 0);
all.sort((a, b) => score(b) - score(a));

if (all.length === 0) {
  console.log("\nno concatenation-into-dynamic-field candidates found; widen sdkGlob.");
} else {
  console.log(`\n${all.length} candidate line(s), highest-risk first:\n`);
  for (const h of all.slice(0, 40)) {
    console.log(`[${score(h)}] ${h.file}:${h.line}\n      ${h.text}`);
  }
}

// ---------------------------------------------------------------- stage 2: execute
if (execIdx > -1 && args[execIdx + 1]) {
  const modPath = path.resolve(repoRoot, args[execIdx + 1]);
  const { pathToFileURL: toUrl } = await import("node:url");
  const mod = await import(toUrl(modPath).href);
  const fnName = args[execIdx + 2];
  const fn = mod[fnName] ?? mod.default?.[fnName];
  if (typeof fn !== "function") {
    console.error(`\n--exec: ${fnName} is not an exported function of ${modPath}`);
    process.exit(1);
  }
  const SAMPLE = [
    ["well-formed", "0x" + "22".repeat(20)],
    ["over-long",   "0x" + "22".repeat(20) + "ff".repeat(16)],
    ["zero-padded", "0x" + "22".repeat(20) + "00".repeat(4)],
    ["empty",       ""],
  ];
  console.log(`\n--exec ${fnName}() — caller-controlled length check:`);
  const lens = new Set();
  for (const [label, depositor] of SAMPLE) {
    let m;
    try {
      // fn(user, nonce, depositId, depositor) shape; adjust per builder under test.
      m = fn("0x" + "11".repeat(20), "42", "0x" + "ab".repeat(32), depositor);
    } catch (e) {
      console.log(`  ${label.padEnd(12)} THREW ${e.message}`);
      continue;
    }
    const bytes = typeof m.data === "string" ? (m.data.length - 2) / 2 : null;
    lens.add(bytes);
    console.log(`  ${label.padEnd(12)} data bytes=${String(bytes).padEnd(4)} id=${String(m.id).slice(0, 18)}...`);
  }
  console.log(
    lens.size > 1
      ? `  => data length is CALLER-CONTROLLED (${[...lens].join(" / ")} bytes) — §5f injection`
      : "  => data length constant; not injectable via this argument",
  );
  console.log("  remember: also check whether the entry id binds the actor (user inside the hash?)");
}
