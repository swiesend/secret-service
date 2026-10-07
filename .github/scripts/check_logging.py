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
# Every module's sources, found rather than listed: a module added later is checked without
# anyone having to remember this file.
SOURCE_ROOTS = sorted(ROOT.glob("*/src/main/java"))

# Identifiers that must never be passed to a logger unwrapped. `label`/`name` are user-chosen
# and go through LogPolicy.label(); the rest are secret material and have no sanctioned form.
SENSITIVE = r"(?:label|itemLabel|collectionLabel|name|collectionName|walletName|secret|pepper|plain|plaintext|password|passphrase|body)"
# The accessor form. `collection.getLabel()` carries exactly the value `label` does, but the
# identifier is `getLabel` -- no word boundary before the capital L -- and the `(?<![.\w])`
# lookbehind on SENSITIVE rejects anything after a dot anyway, so SENSITIVE alone misses it. A
# guardrail that misses it reports the tree clean while labels leak, which is worse than not
# having the rule: the docstring promises concatenation cannot evade it.
# The (?<!getClass\(\)) lookbehind spares getClass().getName() -- a class name, not a user's.
# Any other receiver's getName()/getCollectionName()/getWalletName() carries exactly the value
# the bare identifiers above guard.
SENSITIVE_ACCESSOR = re.compile(
    r"(?<!getClass\(\))\.\s*get(?:Label|Name|CollectionName|WalletName|Secret|Password|Passphrase|Plaintext|Pepper)\s*\(")

LOG_CALL = re.compile(r"\blog\.(?:trace|debug|info|warn|error)\s*\(", re.M)
# Values the policy has already vetted: LogPolicy.label(...), with or without a package
# qualifier. Removed before the sensitive-identifier scan.
SANCTIONED = re.compile(
    # One level of nesting, so the two-argument form with a method call is recognised:
    #   LogPolicy.label(label, item.getObjectPath())
    # A plain [^()]* cannot span the inner parentheses and would reject the recommended usage.
    r"(?:[\w.]*\.)?LogPolicy\.label\s*\((?:[^()]|\([^()]*\))*\)")
GETCLASS_LOGGER = re.compile(r"LoggerFactory\.getLogger\s*\(\s*getClass\s*\(\s*\)\s*\)")

# Opt out of one line with a trailing comment saying why.
ALLOW = re.compile(r"//\s*log-check:\s*allow\b(.*)$")


def log_statements(text):
    """Yield (line_number, statement_text) for each log.* call, balanced to its closing paren."""
    for m in LOG_CALL.finditer(text):
        i = m.end() - 1
        depth, j, in_str, in_char, esc = 0, i, False, False, False
        while j < len(text):
            c = text[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            elif in_char:
                # A char literal can hold '(' or '"'; without this the depth count unbalances.
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == "'":
                    in_char = False
            elif c == '"':
                in_str = True
            elif c == "'":
                in_char = True
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        yield text.count("\n", 0, m.start()) + 1, text[m.start():j + 1]


def strip_strings(s):
    """Blank out string and char literals so their contents never match an identifier rule."""
    s = re.sub(r'"(?:[^"\\]|\\.)*"', '""', s)
    return re.sub(r"'(?:[^'\\]|\\.)*'", "'x'", s)


def strip_comments(text):
    """Blank out comments, keeping line breaks so line numbers stay correct.

    Without this, LOG_CALL matches a log.warn(...) written inside a javadoc example and the rules
    are applied to prose.

    Scanned character by character rather than by regex, because a regex cannot tell a comment
    from a '//' inside a string: a log message containing a URL would have the rest of its line
    blanked -- closing paren included -- and the statement scanner would run on into the
    following lines, reporting violations against code that was never part of the call. A
    guardrail that fails on valid source is worse than no guardrail, because the fix people
    reach for is to stop running it.
    """
    out = []
    i, n = 0, len(text)
    line_comment = block_comment = in_str = in_char = in_text_block = False
    esc = False
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if line_comment:
            if c == "\n":
                line_comment = False
                out.append(c)
            else:
                out.append(" ")
            i += 1
        elif block_comment:
            if c == "*" and nxt == "/":
                block_comment = False
                out.append("  ")
                i += 2
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif in_text_block:
            out.append(c)
            if not esc and text.startswith('"""', i):
                in_text_block = False
                out.append('""')
                i += 3
                continue
            esc = c == "\\" and not esc
            i += 1
        elif in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
        elif in_char:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == "'":
                in_char = False
            i += 1
        elif c == "/" and nxt == "/":
            line_comment = True
            out.append("  ")
            i += 2
        elif c == "/" and nxt == "*":
            block_comment = True
            out.append("  ")
            i += 2
        elif text.startswith('"""', i):
            in_text_block = True
            esc = False
            out.append('"""')
            i += 3
        elif c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif c == "'":
            in_char = True
            out.append(c)
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def check(path):
    raw = path.read_text()
    # Comments are blanked (line-for-line) before any scanning: a log call written inside a javadoc
    # example is documentation, not code, and must not be policed.
    text = strip_comments(raw)
    lines = raw.split("\n")
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
        # into the text. Not preceded by '.', so other.label() is a method call on another
        # type, not the user's label.
        for am in re.finditer(r"(?<![.\w])(" + SENSITIVE + r")\b", code):
            problems.append((n, f"'{am.group(1)}' reaches a logger unwrapped; "
                                f"use LogPolicy.label(...) or do not log it"))
        for am in SENSITIVE_ACCESSOR.finditer(code):
            problems.append((n, f"'{am.group(0).strip()}' reaches a logger unwrapped; "
                                f"use LogPolicy.label(...) or do not log it"))
    return [(rel, n, msg) for n, msg in sorted(set(problems))]


def main():
    files = [p for r in SOURCE_ROOTS for p in r.rglob("*.java")]
    problems = [p for f in files for p in check(f)]
    if problems:
        print(f"Logging policy violations ({len(problems)}):\n", file=sys.stderr)
        for rel, n, msg in problems:
            print(f"  {rel}:{n}: {msg}", file=sys.stderr)
        # Points only at LogPolicy and this file's own docstring: both exist wherever the script
        # does.
        print("\nSee LogPolicy and the rules at the top of this script."
              "\nTo allow one line deliberately, append"
              "\n  // log-check: allow <reason>", file=sys.stderr)
        return 1
    print(f"OK - {len(files)} source files obey the logging policy.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
