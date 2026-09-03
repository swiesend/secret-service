#!/usr/bin/env python3
"""Enforce the logging rules that keep secrets and user-chosen names out of log messages.

Four rules, each of which has already been broken at least once in this repository:

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

4. A log message must be ASCII. A JVM whose native encoding is not UTF-8 replaces every other
   character on the way out, so the text arrives corrupted exactly when someone is reading it
   to diagnose something. Observed: an em dash in ProviderSystemTest printed as

     Provider KeePassXC ? using existing collection id 'test'

   because ubuntu:24.04 leaves LANG unset and the JVM falls back to ANSI_X3.4-1968. Fixing the
   images is necessary but not sufficient -- a consumer embedding this library inherits their
   own process's locale, so the text this library emits must not depend on it.

   This rule alone also covers test sources. The mangling above was in a test, and a test
   message is read at precisely the moment something has gone wrong. The other three rules stay
   on main sources, where the secrets they guard actually live.

   It also catches the \\uXXXX form, which is ASCII in the source and non-ASCII once emitted,
   so scanning the characters alone would let an em dash back in through the side door.

   Not a rule about non-ASCII in general: test data such as "secret" with accents, or
   Japanese and Chinese labels, exists to prove the library carries non-ASCII values intact.
   Only the text this project *emits* is constrained, never the text it is asked to store.

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
# Rule 4 only. Test log messages get mangled by the same mechanism, and are read at exactly the
# moment something has gone wrong; the secrets rules stay off test sources, where fixtures
# legitimately hold the very identifiers those rules forbid.
TEST_SOURCE_ROOTS = ["core/src/test/java", "hardened/src/test/java", "hardened-tpm2/src/test/java"]

# Identifiers that must never be passed to a logger unwrapped. `label`/`name` are user-chosen
# and go through LogPolicy.label(); the rest are secret material and have no sanctioned form.
SENSITIVE = r"(?:label|itemLabel|collectionLabel|name|collectionName|walletName|secret|pepper|plain|plaintext|password|passphrase|body)"
# The accessor form. `collection.getLabel()` carries exactly the value `label` does, but the
# identifier is `getLabel` -- no word boundary before the capital L -- and the `(?<![.\w])`
# lookbehind on SENSITIVE rejects anything after a dot anyway. Six live collection-name leaks sat
# in functional/Collection while the guardrail reported the tree clean, which is worse than not
# having the rule: the docstring promises concatenation cannot evade it.
SENSITIVE_ACCESSOR = re.compile(
    r"\.\s*get(?:Label|Secret|Password|Passphrase|Plaintext|Pepper)\s*\(")

LOG_CALL = re.compile(r"\blog\.(?:trace|debug|info|warn|error)\s*\(", re.M)
# Values the policy has already vetted: LogPolicy.label(...) / LogPolicy.cause(...), with or
# without a package qualifier. Removed before the sensitive-identifier scan.
SANCTIONED = re.compile(
    # One level of nesting, so the two-argument form with a method call is recognised:
    #   LogPolicy.label(label, item.getObjectPath())
    # The previous [^()]* could not span the inner parentheses, so the guardrail rejected its own
    # recommended usage.
    r"(?:[\w.]*\.)?LogPolicy\.(?:label|cause)\s*\((?:[^()]|\([^()]*\))*\)")
GETCLASS_LOGGER = re.compile(r"LoggerFactory\.getLogger\s*\(\s*getClass\s*\(\s*\)\s*\)")
# String literals inside a log statement -- the message text and any literal argument.
STRING_LITERAL = re.compile(r'"(?:[^"\\]|\\.)*"')

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
    from a '//' inside a string. It could not: a log message containing a URL had the rest of its
    line blanked -- closing paren included -- so the statement scanner ran on into the following
    lines and reported violations against code that was never part of the call. A guardrail that
    fails on valid source is worse than no guardrail, because the fix people reach for is to
    stop running it.
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


def check(path, secrets_rules=True):
    """Rule 4 always applies. The secrets rules apply only where secrets live (main sources)."""
    raw = path.read_text()
    # Comments are blanked (line-for-line) before any scanning: a log call written inside a javadoc
    # example is documentation, not code, and must not be policed.
    text = strip_comments(raw)
    lines = raw.split("\n")
    rel = path.relative_to(ROOT)
    problems = []

    if secrets_rules:
        for m in GETCLASS_LOGGER.finditer(text):
            n = text.count("\n", 0, m.start()) + 1
            problems.append((n, "logger named getClass(); name it for the declaring class instead"))

    for n, stmt in log_statements(text):
        if ALLOW.search(lines[n - 1]):
            continue
        # Rule 4, on the literals rather than the code: a non-ASCII identifier is a Java
        # matter, but a non-ASCII character in the emitted text is what gets corrupted.
        for lit in STRING_LITERAL.findall(stmt):
            bad = next((c for c in lit if ord(c) > 127), None)
            if bad is not None:
                problems.append((n, f"non-ASCII {bad!r} (U+{ord(bad):04X}) in a log message; "
                                    f"it becomes '?' under a non-UTF-8 JVM encoding"))
                continue
            # A \\uXXXX escape is ASCII in the source and non-ASCII once emitted, so the
            # scan above cannot see it. Odd backslash count only: in "\\\\u2014" the pair is
            # a literal backslash followed by the characters u2014, which emits nothing odd.
            for esc in re.finditer(r"(\\+)u([0-9a-fA-F]{4})", lit):
                if len(esc.group(1)) % 2 == 1 and int(esc.group(2), 16) > 0x7F:
                    problems.append((n, f"\\u{esc.group(2)} escape in a log message emits a "
                                        f"non-ASCII character; it becomes '?' under a "
                                        f"non-UTF-8 JVM encoding"))
                    break

        if not secrets_rules:
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
        for am in SENSITIVE_ACCESSOR.finditer(code):
            problems.append((n, f"'{am.group(0).strip()}' reaches a logger unwrapped; "
                                f"use LogPolicy.label(...) or do not log it"))
    return [(rel, n, msg) for n, msg in sorted(set(problems))]


def main():
    files = [p for r in SOURCE_ROOTS for p in (ROOT / r).rglob("*.java")]
    test_files = [p for r in TEST_SOURCE_ROOTS for p in (ROOT / r).rglob("*.java")]
    problems = [p for f in files for p in check(f)]
    problems += [p for f in test_files for p in check(f, secrets_rules=False)]
    if problems:
        print(f"Logging policy violations ({len(problems)}):\n", file=sys.stderr)
        for rel, n, msg in problems:
            print(f"  {rel}:{n}: {msg}", file=sys.stderr)
        # Points at LogPolicy and this file's own docstring, both of which exist wherever the
        # script does. It named docs/usage/logging.md, which arrives in a later branch, so on this
        # one the advice sent the reader to a file that was not there.
        print("\nSee LogPolicy and the rules at the top of this script."
              "\nTo allow one line deliberately, append"
              "\n  // log-check: allow <reason>", file=sys.stderr)
        return 1
    print(f"OK - {len(files)} main and {len(test_files)} test source files "
          f"obey the logging policy.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
