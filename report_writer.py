from typing import Dict, List, Iterable
from datetime import datetime
import html
import sys

# HTML REPORT
def write_html_report(findings: List[Dict], output_path: str, language="cf") -> None:
    """Writes findings to a sortable & filterable HTML report."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── build summary (rule ⇒ count) ───────────────────────────────────────
    summary: Dict[str, int] = {}
    for f in findings:
        summary[f["rule"]] = summary.get(f["rule"], 0) + 1
    rule_options = sorted(summary.keys())

    # ── HTML head & styles ────────────────────────────────────────────────
    html_content = f"""<!DOCTYPE html>
 <html lang="en">
 <head>
 <meta charset="UTF-8">"""

    if language == "cf":
        html_content += '<title>Cold Fusion Security Analysis Report</title>'
    elif language == "grails":
        html_content += '<title>Grails Security Analysis Report</title>'
    else:
        html_content += '<title>Qt/C++ Security Analysis Report</title>'

    html_content += f"""
 <style>
  body{{font-family:Arial,Helvetica,sans-serif;margin:2em;background:#fdfdfd}}
  table{{border-collapse:collapse;width:100%}}
  th,td{{border:1px solid #ccc;padding:6px;vertical-align:top}}
  th{{background:#eee;cursor:pointer}}
  .high{{background:#ffe5e5}} .medium{{background:#fffbe5}} .low{{background:#e5f5ff}}
  pre{{margin:0;font-size:0.9em;background:#f8f8f8;padding:6px}}
  .summary-table{{width:auto;margin-bottom:1.5em}}
  .summary-table th{{cursor:auto}}
  #filterBar{{margin:1em 0}}
 </style>
 <script>
 // sortable columns (unchanged)
 document.addEventListener('DOMContentLoaded',function(){{
  const get=(tr,i)=>tr.children[i].innerText||tr.children[i].textContent;
  const cmp=(i,asc)=>(a,b)=>((v1,v2)=>v1!==''&&v2!==''&&!isNaN(v1)&&!isNaN(v2)?v1-v2:v1.localeCompare(v2))
                                   (get(asc?a:b,i),get(asc?b:a,i));
  document.querySelectorAll('table.data thead th').forEach(th=>th.addEventListener('click',function(){{
    const tbl=th.closest('table');
    Array.from(tbl.querySelectorAll('tbody tr'))
      .sort(cmp(Array.from(th.parentNode.children).indexOf(th),this.asc=!this.asc))
      .forEach(tr=>tbl.appendChild(tr));
  }}));

  // filter by rule
  const select=document.getElementById('ruleFilter');
  if(select){{
    select.addEventListener('change',function(){{
      const val=this.value;
      document.querySelectorAll('table.data tbody tr').forEach(tr=>
     {{
        tr.style.display = (!val || tr.dataset.rule===val) ? '' : 'none';
      }});
    }});
  }}
 }});
 </script>
 </head>
 <body>"""
    if language == "cf":
        html_content += '<h1>Cold Fusion Security Analysis Report</h1>'
    elif language == "grails":
        html_content += '<h1>Grails Security Analysis Report</h1>'
    else:
        html_content += '<h1>Qt/C++ Security Analysis Report</h1>'
    html_content += f"""
 
 <p><strong>Generated:</strong> {now}</p>
 <p><strong>Total Findings:</strong> {len(findings)}</p>

 <h2>Summary by Rule</h2>
 <table class="summary-table">
   <thead><tr><th>Rule</th><th>Count</th></tr></thead>
   <tbody>"""

    for rule, cnt in sorted(summary.items(), key=lambda x: (-x[1], x[0])):
        html_content += f"""
     <tr><td>{html.escape(rule)}</td><td>{cnt}</td></tr>"""

    # ── filter bar ────────────────────────────────────────────────────────
    html_content += """
   </tbody>
 </table>

 <div id="filterBar">
   <label for="ruleFilter"><strong>Filter by Rule:</strong></label>
   <select id="ruleFilter">
      <option value="">All</option>"""
    for rule in rule_options:
        html_content += f'\n     <option value="{html.escape(rule)}">{html.escape(rule)}</option>'
    html_content += """
   </select>
 </div>

 <table class="data">
 <thead>
 <tr>
   <th>File</th><th>Line</th><th>Rule</th><th>Severity</th>
   <th>Match</th><th>Reason</th><th>Recommendation</th><th>Context</th>
 </tr>
 </thead>
 <tbody>
 """
    # ── detail rows ───────────────────────────────────────────────────────
    for f in findings:
        sev = html.escape(f["severity"]).lower()
        rule_text = html.escape(f["rule"])
        html_content += f"""
 <tr class="{sev}" data-rule="{rule_text}">
   <td>{html.escape(f["file"])}</td>
   <td>{f["line"]}</td>
   <td>{rule_text}</td>
   <td>{html.escape(f["severity"])}</td>
   <td><pre>{html.escape(f["match"])}</pre></td>
   <td>{html.escape(f["reason"])}</td>
   <td>{html.escape(f["recommendation"])}</td>
   <td><pre>{html.escape(f["context"])}</pre></td>
 </tr>
 """
    html_content += """
 </tbody>
 </table>
 </body>
 </html>
 """
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
    except Exception as e:
        sys.stderr.write(f"[!] Failed to write HTML report: {e}\n")