"""Convert SVG assets to PNG for GitHub README (GitHub blocks SVG in img tags)."""
from pathlib import Path

from playwright.sync_api import sync_playwright

ASSETS = Path(__file__).resolve().parent.parent / "docs" / "assets"

SIZES = {
    "banner.svg": (1100, 280),
    "card-linux.svg": (340, 200),
    "card-ports.svg": (340, 200),
    "card-ftp.svg": (340, 200),
}


def main() -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        for name, (width, height) in SIZES.items():
            svg = ASSETS / name
            png = ASSETS / name.replace(".svg", ".png")
            page.set_viewport_size({"width": width, "height": height})
            page.goto(svg.as_uri())
            page.screenshot(path=str(png), type="png", omit_background=False)
            print(f"Created {png.name} ({width}x{height})")
        browser.close()


if __name__ == "__main__":
    main()
