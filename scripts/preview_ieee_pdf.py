"""
preview_ieee_pdf.py
-------------------
Two-column PDF *preview* of docs/paper_ieee/main.tex for machines without LaTeX. It understands
only the LaTeX subset the paper uses (sections, macros, tables, figures, citations, simple math).
The authoritative PDF is the one LaTeX produces (Overleaf, or tectonic / pdflatex locally).

    python scripts/build_ieee_paper.py && python scripts/preview_ieee_pdf.py
    -> docs/paper_ieee/main_preview.pdf
"""
from __future__ import annotations

import html
import re
from pathlib import Path

import pymupdf

PAPER = Path("docs/paper_ieee")

CSS = """
body { font-family: serif; font-size: 9pt; line-height: 1.22; color: #000; }
h1 { font-size: 20pt; text-align: center; font-weight: normal; margin: 0 0 6pt 0; }
.authors { text-align: center; font-size: 10pt; margin-bottom: 8pt; }
h2 { font-size: 9.5pt; text-align: center; font-variant: small-caps; margin: 8pt 0 3pt 0; }
h3 { font-size: 9pt; font-style: italic; font-weight: normal; margin: 5pt 0 2pt 0; }
p { text-align: justify; margin: 0 0 3pt 0; text-indent: 10pt; }
p.abs { font-weight: bold; font-size: 8.6pt; text-indent: 0; }
p.kw { font-size: 8.6pt; text-indent: 0; }
table { font-size: 7.2pt; border-collapse: collapse; margin: 3pt auto; }
table.wide { font-size: 5.6pt; }
table.wide td { padding: 0.5pt 1.5pt; }
td, th { padding: 1pt 3pt; text-align: center; }
td:first-child { text-align: left; }
tr.head td { border-bottom: 0.6pt solid #000; border-top: 0.8pt solid #000; font-weight: bold; }
tr.last td { border-bottom: 0.8pt solid #000; }
.caption { font-size: 7.6pt; text-align: center; margin: 2pt 0 5pt 0; }
img { width: 100%; }
.ref { font-size: 7.6pt; text-indent: 0; margin-left: 14pt; }
"""


def _read(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"(?<!\\)%.*", "", text)
    return re.sub(r"\\input\{([^}]+)\}", lambda m: _read(PAPER / (m.group(1) if m.group(1).endswith(".tex")
                                                                   else m.group(1) + ".tex")), text)


def _macros(text: str) -> tuple[str, dict]:
    macros = {}
    for name, body in re.findall(r"\\newcommand\{\\([A-Za-z]+)\}\{((?:[^{}]|\{[^{}]*\})*)\}", text):
        macros[name] = body
    text = re.sub(r"\\newcommand\{\\[A-Za-z]+\}\{(?:[^{}]|\{[^{}]*\})*\}", "", text)
    for _ in range(3):
        text = re.sub(r"\\([A-Za-z]+)(\{\})?", lambda m: macros.get(m.group(1), m.group(0)), text)
    return text, macros


def _bib() -> dict[str, str]:
    out = {}
    for key, body in re.findall(r"@\w+\{([^,]+),(.*?)\n\}", (PAPER / "references.bib").read_text(encoding="utf-8"),
                                re.S):
        f = dict(re.findall(r"(\w+)\s*=\s*\{((?:[^{}]|\{[^{}]*\})*)\}", body))
        authors = [a.strip() for a in f.get("author", "").split(" and ") if a.strip()]
        names = []
        for a in authors:
            last, _, first = a.partition(",")
            initials = " ".join(p[0] + "." for p in first.replace("-", " ").split() if p)
            names.append(f"{initials} {last.strip()}".strip())
        who = names[0] + " et al." if len(names) > 3 else ", ".join(names[:-1]) + (" and " if len(names) > 1 else "") + names[-1] if names else ""
        venue = f.get("journal") or f.get("booktitle") or f.get("howpublished") or (
            f"arXiv:{f['eprint']}" if "eprint" in f else "")
        doi = f", doi: {f['doi']}" if "doi" in f else ""
        out[key.strip()] = _clean(f"{who}, ``{f.get('title', '')},'' {venue}, {f.get('year', '')}{doi}.")
    return out


def _clean(s: str) -> str:
    s = s.replace("{", "").replace("}", "").replace("\\%", "%")
    return s.replace("``", "\u201c").replace("''", "\u201d").replace("\\&", "&").replace('\\"o', "ö")


def _inline(s: str) -> str:
    s = re.sub(r"\\(?:emph|textit)\{([^{}]*)\}", r"<i>\1</i>", s)
    s = re.sub(r"\\textbf\{([^{}]*)\}", r"<b>\1</b>", s)
    s = re.sub(r"\\textsc\{([^{}]*)\}", lambda m: m.group(1).upper(), s)
    s = re.sub(r"\\text\{([^{}]*)\}", r"\1", s)
    s = re.sub(r"\$([^$]*)\$", lambda m: _math(m.group(1)), s)
    rep = {"~": " ", "\\%": "%", "\\&": "&", "---": "\u2014", "--": "\u2013", "``": "\u201c", "''": "\u201d",
           "\\,": " ", "\\ ": " ", "\\_": "_", "\\\\": " ", "{,}": ",", "\\textbackslash": "\\"}
    for a, b in rep.items():
        s = s.replace(a, b)
    s = re.sub(r"\\(?:ell)", "\u2113", s)
    s = re.sub(r"\\[A-Za-z]+\*?(\[[^\]]*\])?", "", s)
    return s.replace("{", "").replace("}", "")


def _math(m: str) -> str:
    m = m.replace(r"\{", "&#123;").replace(r"\}", "&#125;")
    rep = {r"\ge": "\u2265", r"\le": "\u2264", r"\ell": "\u2113", r"\#": "#", r"\tilde m": "m\u0303",
           r"\log": "log", r"\max": "max", r"\bigl": "", r"\bigr": "", r"\B": "B", r"\times": "\u00d7"}
    for a, b in rep.items():
        m = m.replace(a, b)
    m = re.sub(r"_\{([^{}]*)\}", r"<sub>\1</sub>", m)
    m = re.sub(r"_([A-Za-z0-9])", r"<sub>\1</sub>", m)
    m = re.sub(r"\^\{([^{}]*)\}", r"<sup>\1</sup>", m)
    m = re.sub(r"\^([A-Za-z0-9])", r"<sup>\1</sup>", m)
    return "<i>" + m + "</i>"


def _table(body: str) -> str:
    body = re.sub(r"\\(toprule|bottomrule)", "", body)
    rows, html_rows = [r.strip() for r in re.split(r"\\\\", body)], []
    first = True
    for r in rows:
        mid = "\\midrule" in r
        r = r.replace("\\midrule", "").strip()
        if not r:
            continue
        cells = [_inline(c.strip()) for c in r.split("&")]
        cls = ' class="head"' if first else ""
        html_rows.append(f"<tr{cls}>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
        first = False if not mid else first
        if mid:
            first = False
    if html_rows:
        html_rows[-1] = html_rows[-1].replace("<tr>", '<tr class="last">', 1)
    wide = max((r.count("<td>") for r in html_rows), default=0) > 6
    return ("<table class='wide'>" if wide else "<table>") + "".join(html_rows) + "</table>"


def _float(block: str) -> str:
    cap = re.search(r"\\caption\{((?:[^{}]|\{[^{}]*\})*)\}", block)
    cap_html = f'<div class="caption">{_inline(cap.group(1))}</div>' if cap else ""
    img = re.search(r"\\includegraphics(?:\[[^\]]*\])?\{([^}]+)\}", block)
    if img:
        return f'<img src="{img.group(1)}"/>' + cap_html
    tab = re.search(r"\\begin\{tabular\}\{[^}]*\}(.*?)\\end\{tabular\}", block, re.S)
    return cap_html + (_table(tab.group(1)) if tab else "")


def convert() -> tuple[str, str]:
    text, _ = _macros(_read(PAPER / "main.tex"))
    bib = _bib()
    order: list[str] = []

    def cite(m):
        keys = [k.strip() for k in m.group(1).split(",")]
        for k in keys:
            if k not in order:
                order.append(k)
        return "[" + ", ".join(str(order.index(k) + 1) for k in keys) + "]"

    text = re.sub(r"\\cite\{([^}]+)\}", cite, text)
    text = re.sub(r"\\(?:label|ref)\{([^}]+)\}", lambda m: "" if m.group(0).startswith("\\label") else
                  {"tab": "", "fig": ""}.get(m.group(1)[:3], "") + _refnum(m.group(1)), text)
    title = _inline(re.search(r"\\title\{(.*?)\}\n", text, re.S).group(1).replace("\\\\", " "))
    authors = re.search(r"\\author\{(.*?)\}\n\n", text, re.S).group(1)
    authors = _inline(re.sub(r"\\IEEEauthorblock[NA]\{", "<br/>", authors).replace("\\\\", "<br/>"))
    body = text.split("\\maketitle", 1)[1].split("\\bibliographystyle", 1)[0]

    floats = []
    body = re.sub(r"\\begin\{(table\*?|figure\*?)\}(.*?)\\end\{\1\}",
                  lambda m: floats.append(_float(m.group(2))) or f"@@FLOAT{len(floats) - 1}@@", body, flags=re.S)
    abstract = re.search(r"\\begin\{abstract\}(.*?)\\end\{abstract\}", body, re.S).group(1)
    kw = re.search(r"\\begin\{IEEEkeywords\}(.*?)\\end\{IEEEkeywords\}", body, re.S).group(1)
    body = body.split("\\end{IEEEkeywords}", 1)[1]

    out, sec = [f'<p class="abs"><i>Abstract</i>\u2014{_inline(abstract.strip())}</p>',
                f'<p class="kw"><b><i>Index Terms</i></b>\u2014{_inline(kw.strip())}</p>'], 0
    roman = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII", "XIII", "XIV", "XV", "XVI"]
    sub = 0
    for para in re.split(r"\n\s*\n", body):
        para = para.strip()
        if not para:
            continue
        for piece in re.split(r"(\\section\{[^}]*\}|\\subsection\{[^}]*\}|@@FLOAT\d+@@)", para):
            piece = piece.strip()
            if not piece:
                continue
            if piece.startswith("\\section"):
                sub = 0
                r_num = roman[sec] if sec < len(roman) else str(sec + 1)
                out.append(f"<h2>{r_num}. {_inline(piece[9:-1]).upper()}</h2>")
                sec += 1
            elif piece.startswith("\\subsection"):
                out.append(f"<h3>{chr(65 + sub)}. {_inline(piece[12:-1])}</h3>")
                sub += 1
            elif piece.startswith("@@FLOAT"):
                out.append(floats[int(piece[7:-2])])
            elif re.sub(r"\\[A-Za-z]+(\{[^}]*\})*", "", piece).strip():
                out.append(f"<p>{_inline(piece)}</p>")
    out.append("<h2>REFERENCES</h2>")
    out += [f'<p class="ref">[{i + 1}] {html.escape(bib.get(k, k))}</p>' for i, k in enumerate(order)]
    head = f"<h1>{title}</h1><div class='authors'>{authors}</div>"
    return head, "".join(out)


_REFS: dict[str, int] = {}


def _refnum(label: str) -> str:
    kind = label.split(":")[0]
    key = f"{kind}:{label}"
    if key not in _REFS:
        _REFS[key] = sum(1 for k in _REFS if k.startswith(kind + ":")) + 1
    return str(_REFS[key])


def main() -> None:
    head, body = convert()
    doc_html = lambda b: f"<html><head><meta charset='utf-8'></head><body>{b}</body></html>"  # noqa: E731
    archive = pymupdf.Archive(str(PAPER))
    out = PAPER / "main_preview.pdf"
    writer = pymupdf.DocumentWriter(str(out))
    page = pymupdf.paper_rect("letter")
    m, gap = 43, 14
    colw = (page.width - 2 * m - gap) / 2
    head_story = pymupdf.Story(doc_html(head), user_css=CSS, archive=archive)
    story = pymupdf.Story(doc_html(body), user_css=CSS, archive=archive)
    n, more, first = 0, True, True
    while more:
        dev = writer.begin_page(page)
        top = m
        if first:
            r = pymupdf.Rect(m, m, page.width - m, m + 110)
            head_story.place(r)
            head_story.draw(dev)
            top, first = m + 110, False
        for x in (m, m + colw + gap):
            if not more:
                break
            more, _ = story.place(pymupdf.Rect(x, top, x + colw, page.height - m))
            story.draw(dev)
        writer.end_page()
        n += 1
    writer.close()
    print(f"wrote {out} ({n} pages, preview layout)")


if __name__ == "__main__":
    main()
