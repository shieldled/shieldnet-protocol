#!/usr/bin/env python3
"""
Render the published specifications in spec/ to standalone HTML.

    python3 tools/build_spec.py OUTDIR [--repo-url URL] [--rev REV] [--pdf CHROME]

One HTML file per spec/*.md, self-contained (inline CSS, no scripts), with a
table of contents and stable heading anchors. Links between the three
specifications are rewritten to the rendered files; links that leave spec/
(design notes, vectors) are rewritten to REPO-URL so they still resolve once the
file is detached from the repository.

With --pdf, each document is also printed to PDF by the headless Chrome/Chromium
at CHROME, with a cover page, running headers and page numbers. The browser
cannot number the table of contents itself, so it prints twice: the first print
carries an invisible marker at each heading, pdftotext finds the page each marker
landed on, and the second print writes those numbers into the contents. The
numbers occupy the contents lines that are already there, so the layout does not
move between the two prints.

Needs Python 3 and markdown-it-py; --pdf also needs pdftotext (poppler-utils).
"""
import argparse, html, pathlib, re, subprocess, sys, tempfile
from markdown_it import MarkdownIt

SPEC = pathlib.Path(__file__).resolve().parent.parent / "spec"
NAMES = {"transport.md": "shieldnet-transport-v1", "message-layer.md": "shieldnet-message-layer-v1",
         "application.md": "shieldled-device-protocol-v1"}

CSS = """
:root { --fg:#1a1a1a; --muted:#555; --rule:#ccc; --code:#f4f4f4; --link:#0b5394; }
html { font-size: 16px; }
body { font-family: Georgia, 'Times New Roman', serif; color: var(--fg); line-height: 1.5;
       max-width: 46rem; margin: 2rem auto; padding: 0 1rem; }
h1, h2, h3, h4 { font-family: Helvetica, Arial, sans-serif; line-height: 1.25; }
h1 { font-size: 1.9rem; margin-bottom: .5rem; }
h2 { font-size: 1.35rem; margin-top: 2.2rem; border-bottom: 1px solid var(--rule); padding-bottom: .2rem; }
h3 { font-size: 1.1rem; margin-top: 1.6rem; }
h4 { font-size: 1rem; }
a { color: var(--link); text-decoration: none; } a:hover { text-decoration: underline; }
code, pre { font-family: Menlo, Consolas, 'DejaVu Sans Mono', monospace; font-size: .85em; }
code { background: var(--code); padding: .05em .25em; border-radius: 2px; }
pre { background: var(--code); padding: .7rem .9rem; overflow-x: auto; line-height: 1.35;
      white-space: pre-wrap; word-break: break-all; }
pre code { background: none; padding: 0; }
table { border-collapse: collapse; margin: 1rem 0; font-size: .92em; width: 100%; }
th, td { border: 1px solid var(--rule); padding: .3rem .55rem; text-align: left; vertical-align: top; }
th { background: #eee; font-family: Helvetica, Arial, sans-serif; }
blockquote { margin: 1rem 0; padding: .1rem 1rem; border-left: 3px solid var(--rule); color: var(--muted); }
hr { border: 0; border-top: 1px solid var(--rule); margin: 2rem 0; }
nav#toc { font-family: Helvetica, Arial, sans-serif; font-size: .9rem; margin: 1.5rem 0 2rem; }
nav#toc ul { list-style: none; padding-left: 0; margin: 0; }
nav#toc li.l3 { padding-left: 1.4rem; }
nav#toc a { display: flex; align-items: baseline; }
nav#toc .leader { flex: 1; border-bottom: 1px dotted var(--rule); margin: 0 .4em; }
.pgmark { position: absolute; font-size: 2px; color: #fff; }
footer { margin-top: 3rem; font-size: .8rem; color: var(--muted); font-family: Helvetica, Arial, sans-serif; }
.cover { display: none; }
@media print {
  body { max-width: none; margin: 0; padding: 0; font-size: 10.5pt; }
  h2, h3, h4 { break-after: avoid; } table, pre, blockquote { break-inside: avoid; }
  a { color: inherit; }
  body > h1:first-of-type, body > h1:first-of-type + table, footer { display: none; }
  nav#toc { break-after: page; }
  .cover { display: flex; flex-direction: column; page: cover; break-after: page; height: 247mm;
           font-family: Helvetica, Arial, sans-serif; }
  .cover .series { font-size: 11pt; letter-spacing: .08em; text-transform: uppercase; color: var(--muted);
                   margin-top: 45mm; }
  .cover .title { font-size: 28pt; font-weight: bold; line-height: 1.15; margin: 6mm 0 8mm;
                  padding-bottom: 6mm; border-bottom: 2px solid var(--fg); }
  .cover .desc { font-family: Georgia, 'Times New Roman', serif; font-size: 13pt; line-height: 1.45; }
  .cover table { width: auto; margin-top: 14mm; font-size: 10.5pt; }
  .cover th, .cover td { border: 0; background: none; padding: 1mm 8mm 1mm 0; }
  .cover th { color: var(--muted); font-weight: normal; }
  .cover .foot { margin-top: auto; font-size: 9pt; color: var(--muted); }
}
"""

# Running header and page numbers for the PDF. Chrome renders CSS page-margin boxes; the
# cover page uses a named page with them cleared.
PAGE_CSS = """
@page {{ size: A4; margin: 22mm 18mm 20mm;
  @top-left {{ content: "{title}"; font: 8pt Helvetica, Arial, sans-serif; color: #555; }}
  @top-right {{ content: "{series}"; font: 8pt Helvetica, Arial, sans-serif; color: #555; }}
  @bottom-center {{ content: "Page " counter(page) " of " counter(pages);
                   font: 8pt Helvetica, Arial, sans-serif; color: #555; }}
}}
@page cover {{ @top-left {{ content: none; }} @top-right {{ content: none; }} @bottom-center {{ content: none; }} }}
"""

def css_string(text):
    return text.replace("\\", "\\\\").replace('"', '\\"')

def slug(text, seen):
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "section"
    n, base = 1, s
    while s in seen:
        n += 1; s = f"{base}-{n}"
    seen.add(s)
    return s

def render(path, repo_url, rev, pages=None, markers=False):
    md = MarkdownIt("commonmark").enable("table")
    tokens = md.parse(path.read_text(encoding="utf-8"))
    seen, toc, title = set(), [], path.stem
    for i, t in enumerate(tokens):
        if t.type == "heading_open":
            text = "".join(c.content for c in tokens[i + 1].children if c.type in ("text", "code_inline"))
            t.attrSet("id", slug(text, seen))
            level = int(t.tag[1])
            if level == 1: title = text
            elif level in (2, 3): toc.append((level, text, t.attrGet("id")))
        if t.type == "inline":
            for c in t.children:
                if c.type != "link_open": continue
                href = c.attrGet("href") or ""
                if re.match(r"[a-z]+:|#", href): continue
                target, _, frag = href.partition("#")
                if target in NAMES:
                    new = NAMES[target] + ".html"
                else:
                    rel = (path.parent / target).resolve().relative_to(SPEC.parent)
                    new = f"{repo_url}/blob/{rev}/{rel.as_posix()}"
                c.attrSet("href", new + ("#" + frag if frag else ""))
    body = md.renderer.render(tokens, md.options, {})
    # a metadata table is written with an empty header row; drop the empty <thead>
    body = re.sub(r"<thead>\s*<tr>\s*(<th></th>\s*)+</tr>\s*</thead>", "", body)
    pages = pages or {}
    nav = "".join(f'<li class="l{l}"><a href="#{i}"><span>{html.escape(t)}</span>'
                  + (f'<span class="leader"></span><span>{pages[i]}</span>' if i in pages else "")
                  + "</a></li>" for l, t, i in toc)
    if markers:
        body = re.sub(r'(<h[23] id="([^"]+)">)', r'\1<span class="pgmark">@@PG:\2@@</span>', body)
    # the table of contents goes after the abstract block: before the first <h2>
    head, sep, rest = body.partition("<h2")
    body = f'{head}<nav id="toc"><strong>Contents</strong><ul>{nav}</ul></nav>{sep}{rest}'
    # the metadata table under the title: | Document | ... |, | Protocol version | ... |, ...
    meta = dict(re.findall(r"^\| ([A-Z][a-z ]+) \| (.+) \|$", path.read_text(encoding="utf-8"), re.M))
    version = meta.get("Protocol version", "")
    rows = "".join(f"<tr><th>{k}</th><td>{md.renderInline(meta[k])}</td></tr>"
                   for k in ("Protocol version", "Status") if k in meta)
    rows += f"<tr><th>Revision</th><td>{html.escape(rev)}</td></tr>"
    cover = f"""<section class="cover">
<div class="series">ShieldNet protocol specification</div>
<div class="title">{html.escape(title)}</div>
<div class="desc">{md.renderInline(meta.get("Document", ""))}</div>
<table>{rows}</table>
<div class="foot">{md.renderInline(meta.get("Copyright", ""))}<br>{html.escape(repo_url)}</div>
</section>"""
    page_css = PAGE_CSS.format(title=css_string(title), series=css_string(f"Version {version}" if version else ""))
    return title, f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title><style>{CSS}{page_css}</style></head>
<body>{cover}{body}
<footer>Rendered from {html.escape(path.name)} at {html.escape(rev)}. Source: {html.escape(repo_url)}</footer>
</body></html>
"""

def print_pdf(chrome, html_path, pdf_path):
    subprocess.run([chrome, "--headless", "--disable-gpu", "--no-pdf-header-footer",
                    "--generate-pdf-document-outline", f"--print-to-pdf={pdf_path}",
                    html_path.resolve().as_uri()], check=True, capture_output=True)

def heading_pages(pdf_path):
    text = subprocess.run(["pdftotext", str(pdf_path), "-"], check=True, capture_output=True,
                          text=True).stdout
    pages = {}
    for n, page in enumerate(text.split("\f"), 1):
        for i in re.findall(r"@@PG:([a-z0-9-]+)@@", re.sub(r"\s+", "", page)):
            pages.setdefault(i, n)
    return pages

def build_pdf(chrome, path, repo_url, rev, pdf_path):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        _, doc = render(path, repo_url, rev, markers=True)
        (tmp / "pass1.html").write_text(doc, encoding="utf-8")
        print_pdf(chrome, tmp / "pass1.html", tmp / "pass1.pdf")
        pages = heading_pages(tmp / "pass1.pdf")
        _, doc = render(path, repo_url, rev, pages=pages)
        (tmp / "pass2.html").write_text(doc, encoding="utf-8")
        print_pdf(chrome, tmp / "pass2.html", pdf_path)
    return pages

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--repo-url", default="https://github.com/shieldled/shieldnet-protocol")
    ap.add_argument("--rev", default="main")
    ap.add_argument("--pdf", metavar="CHROME", help="also print PDF with this browser")
    a = ap.parse_args()
    out = pathlib.Path(a.outdir); out.mkdir(parents=True, exist_ok=True)
    for name, stem in NAMES.items():
        title, doc = render(SPEC / name, a.repo_url.rstrip("/"), a.rev)
        (out / f"{stem}.html").write_text(doc, encoding="utf-8")
        print(f"{stem}.html  {title}")
        if a.pdf:
            build_pdf(a.pdf, SPEC / name, a.repo_url.rstrip("/"), a.rev, (out / f"{stem}.pdf").resolve())
            print(f"{stem}.pdf")

if __name__ == "__main__":
    sys.exit(main())
