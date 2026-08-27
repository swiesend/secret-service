#!/usr/bin/env python3
"""Enforce the logging rules that keep secrets and user-chosen names out of log messages.

Three rules, each of which has already been broken at least once in this repository:

1. A sensitive value must not appear anywhere in a log statement. Item labels and collection
   names go through LogPolicy.label(); peppers, secrets and plaintext go nowhere at all. The
   check looks at the whole statement, not just its argument list, so concatenating a value
   into the message text does not evade it.

2. A log statement must not build its message with String.format. It assembles the text
   whether or not the statement is emitted -- defeating the deferred rendering that keeps a
   suppressed label from ever being built -- and it hides values from a '{}'-shaped search.
   Not hypothetical: the sixth and worst label site in this codebase stayed hidden from a
   manual audit for exactly that reason, and was found by accident.

3. A logger must be named for its declaring class, never getClass(). Logger names are the
   only filtering contract the library offers a consumer's SLF4J backend, and getClass()
   names the runtime subclass instead -- so a configured name silently fails to match.

Deliberately NOT a rule: '+' concatenation in general. It is worth avoiding for the cost of
building messages that are then discarded, but that is a performance matter, and rule 1
already denies it the one thing that would make it a safety matter.

Run from the repository root. Exits 1 on any violation.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE_ROOTS = ["core/src/main/java", "hardened/src/main/java", "hardened-tpm2/src/main/java"]

# Identifiers that must never be passed to a logger unwrapped. `label`/`name` are user-chosen
# and go through LogPolicy.label(); the rest are secret material and have no sanctioned form.
SENSITIVE = r"(?:label|itemLabel|collectionLabel|secret|pepper|plain|plaintext|password|passphrase|body)"

LOG_CALL = re.compile(r"\blog\.(?:trace|debug|info|warn|error)\s*\(", re.M)
# Values the policy has already vetted: LogPolicy.label(...) / LogPolicy.cause(...), with or
# without a package qualifier. Removed before the sensitive-identifier scan.
SANCTIONED = re.compile(r"(?:[\w.]*\.)?LogPolicy\.(?:label|cause)\s*\([^()]*\)")
GETCLASS_LOGGER = re.compile(r"LoggerFactory\.getLogger\s*\(\s*getClass\s*\(\s*\)\s*\)")

# Opt out of one line with a trailing comment saying why.
ALLOW = re.compile(r"//\s*log-check:\s*allow\b(.*)$")


def log_statements(text):
    """Yield (line_number, statement_text) for each log.* call, balanced to its closing paren."""
    for m in LOG_CALL.finditer(text):
        i = m.end() - 1
        depth, j, in_str, esc = 0, i, False, False
        while j < len(text):
            c = text[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        yield text.count("\n", 0, m.start()) + 1, text[m.start():j + 1]


def strip_strings(s):
    """Blank out string literals so their contents never match an identifier rule."""
    return re.sub(r'"(?:[^"\\]|\\.)*"', '""', s)


def check(path):
    text = path.read_text()
    lines = text.split("\n")
    rel = path.relative_to(ROOT)
    problems = []

    for m in GETCLASS_LOGGER.finditer(text):
        n = text.count("\n", 0, m.start()) + 1
        problems.append((n, "logger named getClass(); name it for the declaring class instead"))

    for n, stmt in log_statements(text):
        if ALLOW.search(lines[n - 1]):
            continue
        code = strip_strings(stmt)
        if "String.format" in code:
            problems.append((n, "String.format inside a log call; use SLF4J '{}' parameters"))
        # Values already routed through the policy are, by construction, safe to log.
        code = SANCTIONED.sub("", code)
        # A sensitive identifier anywhere in the statement -- as an argument or concatenated
        # into the text. Not preceded by '.', so Aead.label(...) / kemId.label() are method
        # calls on other types, not the user's label.
        for am in re.finditer(r"(?<![.\w])(" + SENSITIVE + r")\b", code):
            problems.append((n, f"'{am.group(1)}' reaches a logger unwrapped; "
                                f"use LogPolicy.label(...) or do not log it"))
    return [(rel, n, msg) for n, msg in sorted(set(problems))]


def main():
    files = [p for r in SOURCE_ROOTS for p in (ROOT / r).rglob("*.java")]
    problems = [p for f in files for p in check(f)]
    if problems:
        print(f"Logging policy violations ({len(problems)}):\n", file=sys.stderr)
        for rel, n, msg in problems:
            print(f"  {rel}:{n}: {msg}", file=sys.stderr)
        print("\nSee LogPolicy and docs/usage/logging.md. To allow one line deliberately, append"
              "\n  // log-check: allow <reason>", file=sys.stderr)
        return 1
    print(f"OK — {len(files)} source files obey the logging policy.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
