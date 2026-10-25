"""pages: rhtest's reports as a static site, one directory per toolset (the CI workflows' gh-pages).

    python pages.py <site> <toolset>

Puts the last run's fidelity.html at <site>/<toolset>/index.html, each project's full report beside
it as <name>.html, and work/summary.json as summary.json; then remakes <site>/index.html over every
toolset directory the site has, so each workflow adds its own and keeps the others'.
"""
from __future__ import annotations

import datetime
import html
import json
import re
import shutil
import sys
from pathlib import Path

from rhtest import report_path, work_dir

REPO = "https://github.com/zeruth/Rhipper"


def publish(site: Path, toolset: str) -> None:
    out = site / toolset
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    work = work_dir(toolset)
    page = report_path(toolset).read_text(encoding="utf-8")
    # (the overview links each project's report under its work directory; here they sit beside it)
    page = re.sub(r'href="(?:[\w.-]+/)*?([\w.-]+)/build/fidelity\.html"', r'href="\1.html"', page)
    page = re.sub(r"<h1>(.*?)</h1>",
                  lambda m: f'<h1>{m.group(1)}</h1><div class="sub"><a href="../">every toolset</a> · '
                            f'<a href="{REPO}/actions/workflows/{toolset}.yml">workflow</a></div>', page, count=1)
    (out / "index.html").write_text(page, encoding="utf-8")
    for report in sorted(work.glob("*/build/fidelity.html")):
        shutil.copyfile(report, out / f"{report.parents[1].name}.html")
    summary = work / "summary.json"
    if summary.exists():
        shutil.copyfile(summary, out / "summary.json")


def index(site: Path) -> None:
    rows = []
    for d in sorted(p for p in site.iterdir() if p.is_dir() and (p / "index.html").exists()):
        path = d / "summary.json"
        summary = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        passed = sum(1 for e in summary.values() if e.get("status") == "PASS")
        f = [e["fidelity"] for e in summary.values() if e.get("fidelity")]
        translated = sum(x["translated"] for x in f)
        perfect = sum(x["perfect"] for x in f)
        stubs = sum(x["stubs"] for x in f)
        mean = sum(x["mean"] for x in f) / len(f) if f else 0.0
        when = max((e.get("when", "") for e in summary.values()), default="-")
        cls = "pass" if summary and passed == len(summary) else "fail"
        rows.append(f'<tr><td><a href="{html.escape(d.name)}/">{html.escape(d.name)}</a></td>'
                    f'<td class="{cls}">{passed}/{len(summary)}</td><td class="num">{mean:.3f}</td>'
                    f'<td class="num">{perfect}/{translated}</td><td class="num">{stubs}</td>'
                    f'<td class="muted">{html.escape(when)}</td></tr>')
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Rhipper rhtest</title>
<style>
:root {{ --bg:#fbfbfa; --fg:#1d1d1b; --muted:#6b6b66; --line:#e4e3df; --pass:#2f9e5b; --fail:#d0503c; --link:#3f51d8; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#17171a; --fg:#e9e8e4; --muted:#9a9993; --line:#2c2c31; --link:#8f9bff; }} }}
body {{ background:var(--bg); color:var(--fg); font:14px/1.45 system-ui,sans-serif; margin:0; padding:24px 16px; }}
main {{ max-width:900px; margin:0 auto; }} h1 {{ font-size:20px; margin:0 0 4px; }}
.sub {{ color:var(--muted); margin-bottom:16px; }} .wrap {{ overflow-x:auto; }}
table {{ border-collapse:collapse; width:100%; font-size:13px; }}
th,td {{ text-align:left; padding:5px 8px; border-bottom:1px solid var(--line); }}
th {{ color:var(--muted); font-weight:600; }} .num {{ text-align:right; font-variant-numeric:tabular-nums; }}
td:first-child {{ font-family:ui-monospace,monospace; }} a {{ color:var(--link); }}
.muted {{ color:var(--muted); }} .pass {{ color:var(--pass); font-weight:600; }} .fail {{ color:var(--fail); font-weight:600; }}
</style></head><body><main><h1>Rhipper rhtest</h1>
<div class="sub">Programs built from source, run through the whole pipeline, and their ports checked against
them: one row per compiler and target, each from its own workflow. <a href="{REPO}">Rhipper</a> ·
<a href="{REPO}/tree/main/tests/rhtest">rhtest</a>. Updated {now}.</div>
<div class="wrap"><table><thead><tr><th>toolset</th><th>passing</th><th class="num">mean fidelity</th>
<th class="num">at 1.0</th><th class="num">stubs</th><th>run</th></tr></thead><tbody>
{"".join(rows)}
</tbody></table></div></main></body></html>
"""
    (site / "index.html").write_text(page, encoding="utf-8")
    (site / ".nojekyll").write_text("", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    site = Path(sys.argv[1])
    publish(site, sys.argv[2])
    index(site)
    print(f"wrote {site / sys.argv[2]} and {site / 'index.html'}")
