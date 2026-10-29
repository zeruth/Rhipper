"""A project's fidelity report, build/fidelity.html: fidelity32.py's rows, and bytes32.py's where the
project has them (build/bytes32.json).

Two groupings, each a stacked bar of the whole and a row per band, by functions and by code size:
    fidelity       fidelity32's score: 100% (the reference's calls, fields and constants all there),
                   90-99%, ... 0-9%, and the stubs apart
    byte for byte  bytes32's similarity of the gen built for x86 against the reference's own bytes:
                   identical, 90-99%, ... 0-9%, and the functions the x86 build has none of
Then every function in a table the page renders itself (search, kind, sort, pages): 87,000 rows
as HTML froze a browser.

    python fidelity32.py --html-only      the page again from the last build/fidelity.json
"""
from __future__ import annotations

import datetime
import html
import json
from pathlib import Path

# (the bands, best first: label, the lowest score in it, its colour's variable)
SCORE_BANDS = [("100%", 0.999, "b10"), ("90–99%", 0.9, "b9"), ("80–89%", 0.8, "b8"), ("70–79%", 0.7, "b7"),
               ("60–69%", 0.6, "b6"), ("50–59%", 0.5, "b5"), ("40–49%", 0.4, "b4"), ("30–39%", 0.3, "b3"),
               ("20–29%", 0.2, "b2"), ("10–19%", 0.1, "b1"), ("0–9%", 0.0, "b0")]


def band_of(v: float) -> int:
    """the index in SCORE_BANDS of a 0..1 value"""
    return next(i for i, (_l, lo, _c) in enumerate(SCORE_BANDS) if v >= lo)


def grouping(title: str, note: str, groups: list[tuple[str, str, int, int]], total_n: int, total_size: int) -> str:
    """one section: a stacked bar of the whole by size, then a row per group (label, colour class,
    functions, bytes of code)"""
    stack = "".join(
        f'<span class="seg {c}" style="width:{100 * s / total_size:.3f}%" title="{html.escape(l)}: '
        f'{n:,} functions, {100 * s / total_size:.1f}% of the code"></span>'
        for l, c, n, s in groups if s)
    rows = []
    for l, c, n, s in groups:
        fn = 100 * n / total_n if total_n else 0
        sz = 100 * s / total_size if total_size else 0
        rows.append(
            f'<div class="row"><div class="lbl"><i class="dot {c}"></i>{html.escape(l)}</div>'
            f'<div class="track"><div class="fill {c}" style="width:{sz:.3f}%"></div>'
            f'<div class="fill ghost {c}" style="width:{fn:.3f}%"></div></div>'
            f'<div class="v">{n:,}</div><div class="v muted">{fn:.1f}%</div><div class="v">{sz:.1f}%</div></div>')
    return (f'<section><div class="sh"><h2>{html.escape(title)}</h2><span class="muted">{html.escape(note)}</span></div>'
            f'<div class="stack">{stack}</div>'
            f'<div class="row head"><div class="lbl"></div><div class="track muted">bar: share of code by size '
            f'(faint: of functions)</div><div class="v muted">functions</div><div class="v muted">of all</div>'
            f'<div class="v muted">of code</div></div>{"".join(rows)}</section>')


def page(name: str, rows: list, bytes_path: Path | None = None) -> str:
    byt = {}
    if bytes_path is not None and bytes_path.exists():
        for r in json.loads(bytes_path.read_text(encoding="utf-8")):
            byt[f"{r['addr']:08x}" if isinstance(r["addr"], int) else r["addr"].lower()] = r
    total_n = len(rows)
    total_size = sum(r.get("size") or 0 for r in rows) or 1
    scored = [r for r in rows if r["kind"] != "stub"]
    stubs = [r for r in rows if r["kind"] == "stub"]
    perfect = sum(r["score"] >= 0.999 for r in scored)
    mean = sum(r["score"] for r in rows) / total_n if total_n else 0.0
    weighted = sum(r["score"] * (r.get("size") or 0) for r in rows) / total_size

    # fidelity: each band, the stubs apart
    fg = [[l, c, 0, 0] for l, _lo, c in SCORE_BANDS] + [["stub", "stub", 0, 0]]
    for r in rows:
        g = fg[-1] if r["kind"] == "stub" else fg[band_of(r["score"])]
        g[2] += 1
        g[3] += r.get("size") or 0
    sections = [grouping("Fidelity", "each function's calls, fields and constants against the reference's",
                         [tuple(g) for g in fg], total_n, total_size)]

    # byte for byte: bytes32's similarity, identical apart from 100%, and those it has none of
    tiles_bytes = ""
    if byt:
        bg = [["identical", "b10", 0, 0]] + [[l, c, 0, 0] for l, _lo, c in SCORE_BANDS] + [["not built", "stub", 0, 0]]
        same = 0
        sims = []
        for r in rows:
            b = byt.get(r["addr"].lower())
            size = r.get("size") or 0
            if b is None or b.get("kind") in ("stub", "absent"):
                g = bg[-1]
            elif b.get("same"):
                g = bg[0]
                same += 1
            else:
                g = bg[1 + band_of(min(b.get("sim", 0.0), 0.9989))]
            if b is not None:
                sims.append(b.get("sim", 0.0))
            g[2] += 1
            g[3] += size
        bg = [g for g in bg if g[0] != "100%" or g[2]]
        sections.append(grouping("Byte for byte", "the gen built for x86 against the reference's own bytes "
                                 "(bytes32), addresses masked", [tuple(g) for g in bg], total_n, total_size))
        smean = sum(sims) / len(sims) if sims else 0.0
        tiles_bytes = (f'<div class="tile"><b>{same:,}</b><span>byte-identical</span></div>'
                       f'<div class="tile"><b>{100 * smean:.1f}%</b><span>mean byte similarity</span></div>')

    # the table's data, compact: [addr, name, size, kind, score, calls, fields, consts, bytes sim, notes]
    data = []
    for r in rows:
        p = r.get("parts") or {}
        b = byt.get(r["addr"].lower())
        notes = r.get("why") or "; ".join(
            f"{k.replace('_', ' ')}: {', '.join(map(str, r.get(k, [])[:4]))}"
            for k in ("missing_calls", "extra_calls", "missing_fields", "missing_consts") if r.get(k))
        data.append([r["addr"], r["name"], r.get("size") or 0, r["kind"], round(r["score"], 3),
                     p.get("calls"), p.get("fields"), p.get("consts"),
                     None if b is None or b.get("kind") in ("stub", "absent") else round(b.get("sim", 0.0), 3),
                     notes])
    title = html.escape(f"{name} fidelity")
    when = f"{datetime.datetime.now():%Y-%m-%d %H:%M}"
    blob = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    return PAGE.format(title=title, when=when, n=f"{total_n:,}", translated=f"{len(scored):,}",
                       perfect=f"{perfect:,}", stubs=f"{len(stubs):,}", mean=f"{100 * mean:.1f}%",
                       weighted=f"{100 * weighted:.1f}%", tiles_bytes=tiles_bytes,
                       bytes_col="<th data-k=\"8\" class=\"num\">bytes</th>" if byt else "",
                       has_bytes="true" if byt else "false", sections="".join(sections), data=blob)


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>
<style>
:root {{ --bg:#f7f7f5; --card:#fff; --fg:#1b1b19; --muted:#6d6c66; --line:#e6e5e0; --track:#efeee9;
  --b10:#1f9d55; --b9:#56b04a; --b8:#8cbd3f; --b7:#b8c13a; --b6:#d8b532; --b5:#e39a2c; --b4:#e57f2a;
  --b3:#e0632c; --b2:#d84b33; --b1:#c9393b; --b0:#b02a3f; --stub:#8b8a95; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#141416; --card:#1c1c20; --fg:#ecebe7; --muted:#9b9a94;
  --line:#2b2b31; --track:#26262c; --stub:#5f5e6a; }} }}
* {{ box-sizing:border-box; }}
body {{ background:var(--bg); color:var(--fg); font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif; margin:0;
  padding:28px 16px; }}
main {{ max-width:1180px; margin:0 auto; }}
h1 {{ font-size:22px; margin:0 0 2px; letter-spacing:-.01em; }} h2 {{ font-size:16px; margin:0; }}
.sub, .muted {{ color:var(--muted); }} .sub {{ margin-bottom:20px; font-size:13px; }}
.tiles {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(150px,1fr)); gap:10px; margin-bottom:18px; }}
.tile {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:12px 14px; }}
.tile b {{ display:block; font-size:22px; font-variant-numeric:tabular-nums; }} .tile span {{ color:var(--muted); font-size:12px; }}
section {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px 18px; margin-bottom:16px; }}
.sh {{ display:flex; gap:10px; align-items:baseline; flex-wrap:wrap; margin-bottom:12px; }} .sh .muted {{ font-size:12px; }}
.stack {{ display:flex; height:16px; border-radius:8px; overflow:hidden; background:var(--track); margin-bottom:14px; }}
.seg {{ height:100%; }} .seg + .seg {{ box-shadow:inset 1px 0 0 var(--card); }}
.row {{ display:grid; grid-template-columns:110px 1fr 80px 64px 64px; gap:10px; align-items:center; padding:3px 0; }}
.row.head {{ font-size:11px; }} .row.head .track {{ background:none; height:auto; }}
.lbl {{ display:flex; align-items:center; gap:8px; font-variant-numeric:tabular-nums; white-space:nowrap; }}
.dot {{ width:10px; height:10px; border-radius:3px; display:inline-block; }}
.track {{ position:relative; height:10px; background:var(--track); border-radius:5px; overflow:hidden; }}
.fill {{ position:absolute; left:0; top:0; bottom:0; border-radius:5px; }} .fill.ghost {{ opacity:.28; }}
.v {{ text-align:right; font-variant-numeric:tabular-nums; font-size:13px; }}
.b10 {{ background:var(--b10); }} .b9 {{ background:var(--b9); }} .b8 {{ background:var(--b8); }} .b7 {{ background:var(--b7); }}
.b6 {{ background:var(--b6); }} .b5 {{ background:var(--b5); }} .b4 {{ background:var(--b4); }} .b3 {{ background:var(--b3); }}
.b2 {{ background:var(--b2); }} .b1 {{ background:var(--b1); }} .b0 {{ background:var(--b0); }} .stub {{ background:var(--stub); }}
.controls {{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:10px; align-items:center; }}
input, select, button {{ font:inherit; color:inherit; background:var(--bg); border:1px solid var(--line); border-radius:8px;
  padding:6px 10px; }}
input {{ flex:1; min-width:200px; }} button {{ cursor:pointer; }} button:disabled {{ opacity:.4; cursor:default; }}
.wrap {{ overflow-x:auto; }} table {{ border-collapse:collapse; width:100%; font-size:13px; }}
th, td {{ text-align:left; padding:5px 8px; border-bottom:1px solid var(--line); vertical-align:top; }}
th {{ color:var(--muted); font-weight:600; cursor:pointer; user-select:none; white-space:nowrap; }}
th.on::after {{ content:" ↓"; }} th.on.up::after {{ content:" ↑"; }}
.num {{ text-align:right; font-variant-numeric:tabular-nums; }} td.addr {{ font-family:ui-monospace,Consolas,monospace; }}
.pill {{ display:inline-block; min-width:52px; text-align:center; border-radius:6px; padding:1px 6px; color:#fff;
  font-weight:600; font-variant-numeric:tabular-nums; }}
td.notes {{ color:var(--muted); max-width:420px; }}
@media (max-width:640px) {{ .row {{ grid-template-columns:84px 1fr 56px 0 52px; }} .row > .v:nth-child(4) {{ display:none; }} }}
</style></head><body><main>
<h1>{title}</h1>
<div class="sub">Each reference function against its translation. {when}</div>
<div class="tiles">
<div class="tile"><b>{n}</b><span>functions</span></div>
<div class="tile"><b>{translated}</b><span>translated</span></div>
<div class="tile"><b>{perfect}</b><span>at 100% fidelity</span></div>
<div class="tile"><b>{stubs}</b><span>stubs</span></div>
<div class="tile"><b>{mean}</b><span>mean fidelity</span></div>
<div class="tile"><b>{weighted}</b><span>fidelity by size</span></div>
{tiles_bytes}
</div>
{sections}
<section><div class="sh"><h2>Functions</h2><span class="muted" id="count"></span></div>
<div class="controls">
<input id="q" placeholder="search address, name or what differs" autocomplete="off">
<select id="kind"><option value="">all kinds</option><option value="translated">translated</option>
<option value="stub">stubs</option><option value="folded">folded</option><option value="imperfect">below 100%</option></select>
<button id="prev">‹</button><span class="muted" id="pg"></span><button id="next">›</button>
</div>
<div class="wrap"><table><thead><tr><th data-k="0">address</th><th data-k="1">function</th>
<th data-k="2" class="num">size</th><th data-k="4" class="num on up">fidelity</th><th data-k="5" class="num">calls</th>
<th data-k="6" class="num">fields</th><th data-k="7" class="num">consts</th>{bytes_col}<th>what differs</th></tr></thead>
<tbody id="rows"></tbody></table></div></section>
</main>
<script>
const D = {data};
const HAS_BYTES = {has_bytes};
const PER = 200;
let key = 4, up = true, page = 0, view = D;
const css = getComputedStyle(document.documentElement);
const band = v => v >= .999 ? 'b10' : 'b' + Math.max(0, Math.floor(v * 10));
const esc = s => String(s).replace(/[&<>"]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}})[c]);
const num = v => v === null || v === undefined ? '<td class="num muted">–</td>' : `<td class="num">${{(100 * v).toFixed(0)}}%</td>`;
function apply() {{
  const q = document.getElementById('q').value.trim().toLowerCase();
  const k = document.getElementById('kind').value;
  view = D.filter(r => (!k || (k === 'imperfect' ? r[3] !== 'folded' && r[4] < .999 : r[3] === k))
    && (!q || r[0].includes(q) || r[1].toLowerCase().includes(q) || String(r[9]).toLowerCase().includes(q)));
  view.sort((a, b) => {{
    const x = a[key], y = b[key];
    const c = x === y ? b[2] - a[2] : (x === null ? 1 : y === null ? -1 : (x < y ? -1 : 1));
    return up || x === y ? c : -c;
  }});
  page = 0; draw();
}}
function draw() {{
  const pages = Math.max(1, Math.ceil(view.length / PER));
  page = Math.min(page, pages - 1);
  document.getElementById('count').textContent = `${{view.length.toLocaleString()}} of ${{D.length.toLocaleString()}}`;
  document.getElementById('pg').textContent = `${{page + 1}} / ${{pages}}`;
  document.getElementById('prev').disabled = page === 0;
  document.getElementById('next').disabled = page >= pages - 1;
  document.getElementById('rows').innerHTML = view.slice(page * PER, page * PER + PER).map(r => {{
    const score = r[3] === 'stub' ? '<span class="pill stub">stub</span>'
      : `<span class="pill ${{band(r[4])}}">${{(100 * r[4]).toFixed(1)}}%</span>`;
    const by = HAS_BYTES ? (r[8] === null ? '<td class="num muted">–</td>'
      : `<td class="num"><span class="pill ${{band(r[8])}}">${{(100 * r[8]).toFixed(0)}}%</span></td>`) : '';
    return `<tr><td class="addr">${{r[0]}}</td><td>${{esc(r[1])}}</td><td class="num">${{r[2]}}</td>
      <td class="num">${{score}}</td>${{num(r[5])}}${{num(r[6])}}${{num(r[7])}}${{by}}<td class="notes">${{esc(r[9])}}</td></tr>`;
  }}).join('');
}}
let t;
document.getElementById('q').addEventListener('input', () => {{ clearTimeout(t); t = setTimeout(apply, 150); }});
document.getElementById('kind').addEventListener('change', apply);
document.getElementById('prev').addEventListener('click', () => {{ page--; draw(); }});
document.getElementById('next').addEventListener('click', () => {{ page++; draw(); }});
document.querySelectorAll('th[data-k]').forEach(th => th.addEventListener('click', () => {{
  const k = +th.dataset.k;
  up = key === k ? !up : k === 4 || k === 8 || k === 0;
  key = k;
  document.querySelectorAll('th').forEach(h => h.classList.remove('on', 'up'));
  th.classList.add('on'); if (up) th.classList.add('up');
  apply();
}}));
apply();
</script></body></html>
"""
