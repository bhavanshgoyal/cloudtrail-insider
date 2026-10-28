"""
build_docs.py
-------------
Build every generated document from its template, with all numbers filled from results/.

  docs/_templates/THREATS_TO_VALIDITY.md   -> docs/THREATS_TO_VALIDITY.md
  docs/_templates/OBJECTIVES_EVIDENCE.md   -> docs/OBJECTIVES_EVIDENCE.md
  docs/_templates/README_results.md        -> spliced into README.md between markers
  docs/paper_ieee/ (IEEE LaTeX)             -> generated numbers/tables, checks, Overleaf zip,
                                              main_preview.pdf (and main.pdf if a LaTeX engine exists)

    python scripts/build_docs.py            # build
    python scripts/build_docs.py --check    # also fail if any number is unresolved (except the pending triage study)
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from fill_numbers import fill  # noqa: E402

TEMPLATES = Path("docs/_templates")
SIMPLE = {
    "THREATS_TO_VALIDITY.md": Path("docs/THREATS_TO_VALIDITY.md"),
    "OBJECTIVES_EVIDENCE.md": Path("docs/OBJECTIVES_EVIDENCE.md"),
}
README_START, README_END = "<!-- RESULTS:START -->", "<!-- RESULTS:END -->"

def build_simple(check: bool) -> list[str]:
    problems = []
    for name, out in SIMPLE.items():
        src = TEMPLATES / name
        if not src.exists():
            continue
        text, errors = fill(src.read_text(encoding="utf-8"))
        out.write_text(text, encoding="utf-8")
        print(f"  {out}  ({len(errors)} unresolved)")
        problems += errors
    readme_tpl = TEMPLATES / "README_results.md"
    if readme_tpl.exists():
        block, errors = fill(readme_tpl.read_text(encoding="utf-8"))
        readme = Path("README.md").read_text(encoding="utf-8")
        if README_START in readme and README_END in readme:
            pre, rest = readme.split(README_START, 1)
            _, post = rest.split(README_END, 1)
            Path("README.md").write_text(pre + README_START + "\n" + block + "\n" + README_END + post,
                                         encoding="utf-8")
            print(f"  README.md results block  ({len(errors)} unresolved)")
        else:
            problems.append("README.md has no RESULTS markers")
        problems += errors
    return problems


def build_paper() -> tuple[list[str], int]:
    import subprocess

    import pymupdf

    errors = []
    for script in ("scripts/build_ieee_paper.py", "scripts/preview_ieee_pdf.py"):
        r = subprocess.run([sys.executable, script], capture_output=True, text=True)
        out = (r.stdout + r.stderr).strip()
        print("  " + out.replace("\n", "\n  "))
        if r.returncode:
            return [f"{script} failed"], 0
        errors += [line.strip() for line in r.stdout.splitlines()
                   if "undefined macro" in line or ".tex: " in line and "missing" in line]
    pages = len(pymupdf.open("docs/paper_ieee/main_preview.pdf"))
    return errors, pages


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    print("building documents")
    problems = build_simple(args.check)
    errs, pages = build_paper()
    problems += errs
    pending = [p for p in problems if "triage" in p.lower()]
    hard = [p for p in problems if p not in pending]
    for p in hard:
        print("  UNRESOLVED:", p)
    if not 4 <= pages <= 8:
        print(f"  WARNING: paper preview is {pages} pages (IEEE two-column; the rubric asks for 6-8 pages)")
    if args.check and hard:
        sys.exit(1)


if __name__ == "__main__":
    main()
