"""
build_docs.py
-------------
Build every generated document from its template, with all numbers filled from results/.

  docs/_templates/THREATS_TO_VALIDITY.md   -> docs/THREATS_TO_VALIDITY.md
  docs/_templates/OBJECTIVES_EVIDENCE.md   -> docs/OBJECTIVES_EVIDENCE.md
  docs/_templates/PROJECT_SUMMARY_FOR_PPT.md -> docs/PROJECT_SUMMARY_FOR_PPT.md
  docs/_templates/README_results.md        -> spliced into README.md between markers
  docs/_templates/paper.md                 -> docs/paper/paper.md, paper.html, paper.pdf (A4, page count checked)

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
    "PROJECT_SUMMARY_FOR_PPT.md": Path("docs/PROJECT_SUMMARY_FOR_PPT.md"),
}
README_START, README_END = "<!-- RESULTS:START -->", "<!-- RESULTS:END -->"

PAPER_CSS = """
@page { size: A4; margin: 16mm 15mm; }
body { font-family: serif; font-size: 9.6pt; line-height: 1.32; color: #111; }
h1 { font-size: 15pt; margin: 0 0 4pt 0; }
h2 { font-size: 11.5pt; margin: 10pt 0 3pt 0; }
h3 { font-size: 10pt; margin: 7pt 0 2pt 0; }
p, li { margin: 2pt 0; text-align: justify; }
table { border-collapse: collapse; margin: 4pt 0; font-size: 8pt; width: 100%; }
th, td { border: 0.5pt solid #999; padding: 1.5pt 3pt; text-align: left; }
th { background: #eee; }
img { width: 100%; }
pre, code { font-family: monospace; font-size: 7.8pt; }
pre { background: #f4f4f4; padding: 3pt; }
hr { border: 0; border-top: 0.5pt solid #999; }
"""


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


def _md_spacing(text: str) -> str:
    """Python-Markdown needs a blank line before a list and after an image to start a new block."""
    out, in_code = [], False
    item = re.compile(r"^\s*([-*]|\d+\.)\s")
    for line in text.splitlines():
        if line.startswith("```"):
            in_code = not in_code
        prev = out[-1] if out else ""
        if not in_code and prev.strip():
            new_list = item.match(line) and not item.match(prev) and not prev.startswith("  ")
            if new_list or prev.lstrip().startswith("!["):
                out.append("")
        out.append(line)
    return "\n".join(out)


def build_paper() -> tuple[list[str], int]:
    import pymupdf as fitz
    import markdown

    out_dir = Path("docs/paper")
    out_dir.mkdir(parents=True, exist_ok=True)
    text, errors = fill((TEMPLATES / "paper.md").read_text(encoding="utf-8"))
    (out_dir / "paper.md").write_text(text, encoding="utf-8")

    html_body = markdown.markdown(_md_spacing(text), extensions=["tables", "fenced_code"])
    # images: markdown paths are relative to docs/paper; the PDF archive is rooted at the repo
    html_body = re.sub(r'src="\.\./\.\./', 'src="', html_body)
    html = f"<html><head><meta charset='utf-8'><style>{PAPER_CSS}</style></head><body>{html_body}</body></html>"
    (out_dir / "paper.html").write_text(html.replace('src="figures/', 'src="../../figures/'), encoding="utf-8")

    story = fitz.Story(html=html, user_css=PAPER_CSS, archive=fitz.Archive("."))
    writer = fitz.DocumentWriter(str(out_dir / "paper.pdf"))
    mediabox = fitz.paper_rect("a4")
    where = mediabox + (43, 45, -43, -45)
    pages, more = 0, True
    while more:
        dev = writer.begin_page(mediabox)
        more, _ = story.place(where)
        story.draw(dev)
        writer.end_page()
        pages += 1
    writer.close()
    print(f"  docs/paper/paper.pdf  ({pages} pages, {len(errors)} unresolved)")
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
    if not 6 <= pages <= 8:
        print(f"  WARNING: paper is {pages} pages; the rubric asks for 6-8")
    if args.check and hard:
        sys.exit(1)


if __name__ == "__main__":
    main()
