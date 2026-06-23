"""Fix TOC anchor links for MkDocs/GitHub compatibility."""
import re
from pathlib import Path

DOCS = Path(__file__).resolve().parent.parent / "docs"

for name in ("linux-cheatsheet.md", "ports.md", "ftp-cheatsheet.md"):
    fp = DOCS / name
    text = fp.read_text(encoding="utf-8")

    text = re.sub(r" \{#seccion-\d+\}", "", text)
    text = re.sub(
        r"^## SECCIÓN (\d+): (.+)$",
        lambda m: f"## SECCIÓN {m.group(1)}: {m.group(2)} {{#seccion-{m.group(1)}}}",
        text,
        flags=re.MULTILINE,
    )

    def fix_toc_line(line: str) -> str:
        m = re.match(r"^(\d+\. \[.+?\]\(#)sección-(\d+)[^)]*(\).*)$", line)
        if not m:
            return line
        return f"{m.group(1)}seccion-{m.group(2)}{m.group(3)}"

    text = "\n".join(fix_toc_line(line) for line in text.splitlines())
    fp.write_text(text, encoding="utf-8")
    print(f"Updated {name}")
