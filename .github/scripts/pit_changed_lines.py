#!/usr/bin/env python3
"""Point PIT's mutation tests at the lines a pull request changes.

PIT mutates whole classes. This picks the classes from the diff, and reports on
the changed lines only, so new code is judged and old code is not graded.

  targets --base REF --module DIR --lines FILE
      Diffs REF against HEAD in DIR/src/main/java. Writes each added or changed
      line of a Java file there to FILE, as JSON, and prints "classes=..." with
      PIT's targetClasses for those files, for $GITHUB_OUTPUT. The value is empty
      when no such line changed.

  report --module DIR --lines FILE --summary FILE [--pit-outcome OUTCOME] MUTATIONS_XML
      Appends a Markdown summary of the mutants on the changed lines to the summary
      file, for $GITHUB_STEP_SUMMARY: how many PIT made there, how many a test
      detected, and each one that survived or that no test reached. Each of those
      also becomes a warning annotation on its line, printed to stdout. OUTCOME is
      the outcome of PIT's step: after a "success", a missing report means that
      PIT found nothing to mutate.

Mutants on the other lines of these classes are in PIT's own report only.
"""
import argparse
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
NOT_CLASSES = {"module-info.java", "package-info.java"}
# PIT counts a mutant that makes a test time out or run out of memory as detected.
DETECTED = {"KILLED", "TIMED_OUT", "MEMORY_ERROR"}
# A mutant that no test detected: the tests ran it, or none of them reaches its line.
UNDETECTED = {"SURVIVED": "survived", "NO_COVERAGE": "not reached"}


def source_root(module):
    return f"{module}/src/main/java"


def plural(count, word):
    return f"{count} {word}" + ("" if count == 1 else "s")


def changed_lines(base, root):
    """Each added or modified Java file under root, with the lines HEAD adds or changes in it."""
    diff = subprocess.run(
        ["git", "diff", "--unified=0", "--no-color", "--no-ext-diff", "--no-renames",
         "--diff-filter=AM", base, "HEAD", "--", root],
        check=True, capture_output=True, text=True).stdout
    lines = {}
    path = None
    header = False
    for row in diff.splitlines():
        # A changed line starts with + or -, so only the header of a file, between its
        # "diff --git" line and its first hunk, can name the file.
        if row.startswith("diff --git "):
            path, header = None, True
        elif header and row.startswith("+++ "):
            # A renamed file counts as added (--no-renames). git quotes an unusual name,
            # which no Java source file has.
            name = row[4:]
            path = name[2:] if name.startswith("b/") else None
        elif row.startswith("@@"):
            header = False
            hunk = HUNK.match(row)
            if path is not None and hunk:
                start, count = int(hunk[1]), int(hunk[2] or 1)
                lines.setdefault(path, set()).update(range(start, start + count))
    return {p: sorted(n) for p, n in sorted(lines.items())
            if p.endswith(".java") and PurePosixPath(p).name not in NOT_CLASSES and n}


def class_name(path, root):
    return str(PurePosixPath(path).relative_to(root).with_suffix("")).replace("/", ".")


def targets(args):
    root = source_root(args.module)
    lines = changed_lines(args.base, root)
    with open(args.lines, "w", encoding="utf-8") as out:
        json.dump(lines, out, indent=1)
    classes = []
    for path in lines:
        name = class_name(path, root)
        classes += [name, name + "$*"]
    print(f"{args.module}: {plural(sum(map(len, lines.values())), 'changed line')} in "
          f"{plural(len(lines), 'file')}", file=sys.stderr)
    print("classes=" + ",".join(classes))


def mutants(xml_path, root, lines):
    """The mutants that PIT made on a changed line: (path, line, status, mutator, description)."""
    changed = {path: set(numbers) for path, numbers in lines.items()}
    for mutation in ET.parse(xml_path).getroot().iter("mutation"):
        mutated = mutation.findtext("mutatedClass", "")
        package = mutated.rsplit(".", 1)[0].replace(".", "/") if "." in mutated else ""
        path = str(PurePosixPath(root, package, mutation.findtext("sourceFile", "")))
        line = int(mutation.findtext("lineNumber", "0"))
        if line in changed.get(path, ()):
            yield (path, line, mutation.get("status", ""),
                   mutation.findtext("mutator", "").rsplit(".", 1)[-1],
                   mutation.findtext("description", ""))


def cell(text):
    """Text that a Markdown table cell shows as it is."""
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("|", "\\|").replace("\n", " "))


def command_value(text, prop=False):
    """Text escaped for a workflow command, as the runner unescapes it."""
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return text.replace(":", "%3A").replace(",", "%2C") if prop else text


def report(args):
    root = source_root(args.module)
    with open(args.lines, encoding="utf-8") as f:
        lines = json.load(f)
    out = [f"### Mutation tests on the changed lines of {args.module}", ""]
    try:
        found = sorted(mutants(args.mutations_xml, root, lines))
    except (OSError, ET.ParseError) as e:
        if isinstance(e, FileNotFoundError) and args.pit_outcome == "success":
            # PIT writes no report when it makes no mutant at all.
            out.append("PIT found nothing to mutate in the changed classes, such as an "
                       "interface without a method body.")
        else:
            out.append(f"PIT wrote no report to read ({type(e).__name__}); its log is in "
                       f"the step before.")
        found = None
    if found is not None:
        changed = (f"{plural(sum(map(len, lines.values())), 'changed line')} in "
                   f"{plural(len(lines), 'file')}")
        missed = [m for m in found if m[2] in UNDETECTED]
        if found:
            counts = [f"{sum(m[2] in DETECTED for m in found)} detected",
                      f"{sum(m[2] == 'SURVIVED' for m in missed)} survived",
                      f"{sum(m[2] == 'NO_COVERAGE' for m in missed)} not reached by the tests "
                      f"that PIT runs"]
            untested = sum(m[2] not in DETECTED and m[2] not in UNDETECTED for m in found)
            if untested:
                counts.append(f"{untested} that PIT could not test")
            out.append(f"PIT made {plural(len(found), 'mutant')} on {changed}: "
                       f"{', '.join(counts)}.")
        else:
            out.append(f"PIT made no mutant on {changed}, as nothing there is code that PIT "
                       f"mutates: a comment, an import or a declaration, for example.")
        if missed:
            out += ["", "| Line | Mutator | Mutation | Result |", "|---|---|---|---|"]
            for path, line, status, mutator, description in missed:
                # A code span shows its text as it is; a Java source path needs no escape.
                where = PurePosixPath(path).relative_to(root)
                out.append(f"| `{where}:{line}` | {cell(mutator)} | {cell(description)} "
                           f"| {UNDETECTED[status]} |")
                print(f"::warning file={command_value(path, True)},line={line},"
                      f"title={command_value('Mutant ' + UNDETECTED[status], True)}::"
                      f"{command_value(description)}")
    with open(args.summary, "a", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    t = commands.add_parser("targets")
    t.add_argument("--base", required=True)
    t.add_argument("--module", required=True)
    t.add_argument("--lines", required=True)
    r = commands.add_parser("report")
    r.add_argument("--module", required=True)
    r.add_argument("--lines", required=True)
    r.add_argument("--summary", required=True)
    r.add_argument("--pit-outcome")
    r.add_argument("mutations_xml")
    args = parser.parse_args()
    if args.command == "targets":
        targets(args)
    else:
        report(args)


if __name__ == "__main__":
    main()
