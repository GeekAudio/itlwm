"""Build a coherent, self-contained site snapshot with a content revision."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ASSETS = ("assets/site.css", "data.js", "assets/test-records.js",
          "assets/site.js", "assets/freshness.js")


def render_site(site: Path, updated_at: str) -> str:
    dist = site / "dist"
    template = (site / "templates/index.html").read_text(encoding="utf-8")
    assets = {name: (dist / name).read_text(encoding="utf-8") for name in ASSETS}
    page = template.replace("<!-- site-freshness -->", "<script>\n" +
                        assets["assets/freshness.js"].replace("</script", "<\\/script") +
                        "\n</script>")
    page = page.replace('<link rel="stylesheet" href="./assets/site.css">',
                        "<style>\n" + assets["assets/site.css"] + "\n</style>")
    scripts = []
    for name in ("data.js", "assets/test-records.js", "assets/site.js"):
        page = page.replace(f'  <script src="./{name}" defer></script>\n', "")
        scripts.append("<script>\n" + assets[name].replace("</script", "<\\/script") +
                       "\n</script>")
    page = page.replace("</body>", "\n".join(scripts) + "\n</body>")
    version = hashlib.sha256(page.encode()).hexdigest()
    page = page.replace("<!-- site-version -->",
                        f'<meta name="iw-site-version" content="{version}">')
    # Both entry points contain one coherent data/style/script version. Cached
    # loose assets can no longer mix a new page with an old data.js.
    for name in ("index.html", "milestones.html"):
        (dist / name).write_text(page, encoding="utf-8")
    names = ("index.html", "milestones.html", *ASSETS)
    manifest = {"schema": 1, "version": version, "updatedAt": updated_at,
                "files": {name: hashlib.sha256((dist / name).read_bytes()).hexdigest()
                          for name in names}}
    (dist / "site-version.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return version
