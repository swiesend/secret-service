#!/usr/bin/env python3
"""Compile every ```java fence in docs/ against the built artifacts.

Prose drifts from the API silently: a private method, a renamed builder flag or a
changed return type keeps rendering perfectly in Markdown. This turns every
documented snippet into a compilation unit, so the docs break the build instead of
misleading a reader.

Snippets are fragments, not programs, so each is wrapped:
  - `import` lines are hoisted to the top of the generated file;
  - a snippet that already declares a top-level type is compiled as-is;
  - anything else becomes the body of a method, with a small set of stub symbols
    (see STUBS) so illustrative names like `httpClient` need not be declared inline.

Opt out of a single fence with an HTML comment on the line before it:
    <!-- docs-compile: skip reason goes here -->
Use sparingly, and always say why.
"""
import pathlib, re, subprocess, sys, tempfile, shutil

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
SKIP = re.compile(r"<!--\s*docs-compile:\s*skip(.*?)-->", re.I)

# NB: `de.swiesend.secretservice.functional` is imported class-by-class, never with a
# wildcard -- it contains a class named `System`, which a wildcard makes ambiguous with
# `java.lang.System`. That ambiguity is real for consumers too, but it is not the
# snippet's bug, so the harness must not manufacture it.
# Docs omit imports on purpose -- a landing-page teaser cluttered with 8 import lines
# teaches nothing. Inject the library's own packages plus the usual java.* so snippets
# stay readable while still being type-checked.
DEFAULT_IMPORTS = """
import java.util.*;
import java.util.function.*;
import java.nio.file.*;
import java.security.*;
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.Session;
import de.swiesend.secretservice.functional.Collection;
import de.swiesend.secretservice.functional.SearchMode;
import de.swiesend.secretservice.functional.interfaces.*;
import de.swiesend.secretservice.simple.*;
import de.swiesend.secretservice.hardened.*;
import de.swiesend.secretservice.hardened.providers.*;
import de.swiesend.secretservice.hardened.tpm2.*;
import tss.*;
"""

# Free identifiers that snippets use illustratively.
#
# RULE: only ever stub symbols that belong to the READER'S application (`grantAccess()`,
# `httpClient`) or that carry over from an earlier snippet on the same page (`base`,
# `coll`). NEVER stub a symbol from this library -- that is precisely what the check
# exists to verify, and a stub would hide the next renamed method or changed return type.
STUBS = """
    static char[] typedByUser = new char[0];
    static char[] ownerPw = new char[0];
    static char[] unsealPw = new char[0];
    static char[] sealPassword = new char[0];
    static char[] fetchUnsealPassword() { return new char[0]; }
    static final Http httpClient = new Http();
    static class Http { void authorize(char[] c) {} }
    // Continuation variables: several pages show a short follow-on snippet that reuses the
    // collection and provider established by the page's first example.
    static de.swiesend.secretservice.functional.interfaces.CollectionInterface base = null;
    static de.swiesend.secretservice.functional.interfaces.CollectionInterface collection = null;
    static String path = "/org/freedesktop/secrets/collection/default/1";
    static de.swiesend.secretservice.hardened.KeyMaterialProvider provider = null;
    static de.swiesend.secretservice.hardened.HardenedCollection coll = null;
    static String itemPath = "/org/freedesktop/secrets/collection/default/1";
    static char[] readUserInput() { return new char[0]; }
    static char[] candidate = new char[0];
    static void grantAccess() {}
    static void showLoginError() {}
    static de.swiesend.secretservice.hardened.tpm2.Tpm2GenerationAnchor anchor = null;
    static de.swiesend.secretservice.hardened.tpm2.Tpm2KeyMaterialProvider tpm = null;
    static java.nio.file.Path blobPath = java.nio.file.Path.of("/etc/myapp/pepper.tpm2blob");
    static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger("docs");
"""

def fences(md: pathlib.Path):
    lines = md.read_text().split("\n")
    i = 0
    while i < len(lines):
        if lines[i].strip() == "```java":
            skip = None
            for back in (i - 1, i - 2):
                if back >= 0 and SKIP.search(lines[back]):
                    skip = SKIP.search(lines[back]).group(1).strip() or "(no reason given)"
            j = i + 1
            while j < len(lines) and lines[j].strip() != "```":
                j += 1
            yield i + 1, "\n".join(lines[i + 1:j]), skip
            i = j + 1
        else:
            i += 1

def wrap(body: str, name: str):
    """Returns (source, filename_stem). A snippet that declares a type is compiled as
    written -- only de-`public`ed so the filename need not match."""
    imports = [l for l in body.split("\n") if l.strip().startswith("import ")]
    rest = "\n".join(l for l in body.split("\n") if not l.strip().startswith("import "))
    head = DEFAULT_IMPORTS + "\n".join(imports)
    decl = re.search(r"^\s*(public\s+)?(final\s+)?(class|interface|enum|record)\s+(\w+)", rest, re.M)
    if decl:
        rest = re.sub(r"^(\s*)public\s+(final\s+)?(class|interface|enum|record)\s",
                      r"\1\2\3 ", rest, flags=re.M)
        return f"{head}\nclass {name} {{{STUBS}}}\n{rest}\n", name
    return (f"{head}\nclass {name} {{{STUBS}\n    void run() throws Exception {{\n{rest}\n    }}\n}}\n",
            name)

def main() -> int:
    cp_file = ROOT / "target" / "docs-cp.txt"
    if not cp_file.exists():
        print(f"classpath file missing: {cp_file}", file=sys.stderr)
        print("run:  mvn -q -pl core,hardened,hardened-tpm2 -am dependency:build-classpath "
              f"-Dmdep.outputFile={cp_file} -Dmdep.regenerateFile=true", file=sys.stderr)
        return 2
    cp = cp_file.read_text().strip()
    for m in ("core", "hardened", "hardened-tpm2"):
        cp = f"{ROOT/m/'target'/'classes'}:{cp}"

    work = pathlib.Path(tempfile.mkdtemp(prefix="docsnip-"))
    units, skipped = [], []
    for md in sorted(DOCS.rglob("*.md")):
        for n, (line, body, skip) in enumerate(fences(md)):
            tag = f"{md.relative_to(ROOT)}:{line}"
            if skip is not None:
                skipped.append((tag, skip)); continue
            name = re.sub(r"\W", "_", f"S_{md.stem}_{line}")
            src, stem = wrap(body, name)
            f = work / f"{stem}.java"
            f.write_text(src)
            units.append((f, tag))

    if not units:
        print("no snippets found — extractor is broken", file=sys.stderr); return 2

    r = subprocess.run(["javac", "-nowarn", "-proc:none", "-d", str(work / "out"),
                        "-cp", cp, *[str(f) for f, _ in units]],
                       capture_output=True, text=True)
    owner = {f.name: tag for f, tag in units}
    if r.returncode != 0:
        print(f"\n{len(units)} snippet(s) compiled, FAILURES:\n")
        for line in r.stderr.split("\n"):
            m = re.match(r"(\S+\.java):(\d+): (error.*)", line)
            print(f"  {owner.get(pathlib.Path(m.group(1)).name, m.group(1))}  ->  {m.group(3)}"
                  if m else (f"    {line}" if line.strip() else ""))
        shutil.rmtree(work, ignore_errors=True)
        return 1
    print(f"OK — {len(units)} documented snippet(s) compile against the built artifacts.")
    for tag, why in skipped:
        print(f"  skipped {tag}: {why}")
    shutil.rmtree(work, ignore_errors=True)
    return 0

sys.exit(main())
