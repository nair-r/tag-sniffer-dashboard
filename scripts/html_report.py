"""
DICOM Tag Sniffer — Standalone HTML Report Generator

Produces a self-contained HTML file with embedded CSS and collapsible
<details> sections. No JavaScript, no external dependencies — opens
in any browser.
"""

import os
from datetime import datetime
from html import escape

from dashboard import (
    parse_standard_elements,
    parse_private_elements,
    parse_sequences,
    parse_date_time,
    parse_simple_list,
    parse_counts,
    parse_private_creators,
    parse_large_private_elements,
    parse_scan_summary,
    PHI_GROUPS,
)

# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    max-width: 1100px;
    margin: 0 auto;
    padding: 20px 30px;
    color: #000337;
    background: #FAFBFF;
    line-height: 1.5;
}
h1 { color: #7BA7CC; border-bottom: 2px solid #7BA7CC; padding-bottom: 8px; }
h2 { color: #000337; margin-top: 30px; border-left: 4px solid #FF702A; padding-left: 12px; }
h3 { color: #000337; margin-top: 20px; border-left: 3px solid #FFA929; padding-left: 10px; }
.header-info {
    background: #E8F0FE;
    padding: 12px 18px;
    border-radius: 6px;
    margin-bottom: 20px;
    font-size: 0.95em;
    border-left: 4px solid #2C82FD;
}
.header-info span { margin-right: 30px; }
.metrics {
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    margin: 16px 0;
}
.metric {
    background: white;
    border: 1px solid #D0DDEF;
    border-radius: 8px;
    padding: 14px 20px;
    min-width: 140px;
    text-align: center;
    border-top: 3px solid #2C82FD;
}
.metric .value { font-size: 1.8em; font-weight: 700; color: #000337; }
.metric .label { font-size: 0.85em; color: #555; margin-top: 2px; }
details {
    background: white;
    border: 1px solid #D0DDEF;
    border-radius: 6px;
    margin: 10px 0;
    padding: 0;
}
details > summary {
    padding: 12px 16px;
    cursor: pointer;
    font-weight: 600;
    font-size: 1.05em;
    background: #E8F0FE;
    color: #000337;
    border-radius: 6px;
    list-style: none;
}
details > summary::-webkit-details-marker { display: none; }
details > summary::before { content: "\\25B6  "; font-size: 0.8em; color: #2C82FD; }
details[open] > summary::before { content: "\\25BC  "; color: #2C82FD; }
details[open] > summary { border-bottom: 1px solid #D0DDEF; border-radius: 6px 6px 0 0; }
details > .content { padding: 12px 16px; }
.tag-row { margin: 8px 0; padding: 6px 0; border-bottom: 1px solid #E8F0FE; }
.tag-header { display: flex; justify-content: space-between; align-items: center; }
.tag-label { font-weight: 600; font-family: monospace; font-size: 0.95em; color: #000337; }
.tag-vr { color: #888; font-family: monospace; font-size: 0.85em; margin-left: 8px; }
.status-clean {
    display: inline-block;
    background: #E0F2E9;
    color: #155724;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.8em;
    font-weight: 600;
}
.status-review {
    display: inline-block;
    background: #FFF0D9;
    color: #7A4D00;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.8em;
    font-weight: 600;
    border: 1px solid #FFA929;
}
.values { margin: 4px 0 0 20px; font-family: monospace; font-size: 0.9em; color: #333; max-height: 200px; overflow-y: auto; }
.values div { padding: 1px 0; }
.table-scroll {
    max-height: 400px;
    overflow-y: auto;
    margin: 10px 0;
    border: 1px solid #D0DDEF;
    border-radius: 6px;
}
table {
    border-collapse: collapse;
    width: 100%;
    margin: 0;
    font-size: 0.9em;
}
.table-scroll table th {
    position: sticky;
    top: 0;
    z-index: 1;
}
th, td {
    border: 1px solid #D0DDEF;
    padding: 8px 12px;
    text-align: left;
}
th { background: #E8F0FE; font-weight: 600; color: #000337; }
tr:nth-child(even) { background: #F5F8FF; }
.section-divider { border-top: 2px solid #D0DDEF; margin: 30px 0; }
.warning-box {
    background: #FFF0D9;
    border: 1px solid #FFA929;
    border-radius: 6px;
    padding: 10px 14px;
    margin: 10px 0;
    font-size: 0.9em;
}
.success-box {
    background: #E0F2E9;
    border: 1px solid #28a745;
    border-radius: 6px;
    padding: 10px 14px;
    margin: 10px 0;
    font-size: 0.9em;
}
.info-box {
    background: #E8F0FE;
    border: 1px solid #2C82FD;
    border-radius: 6px;
    padding: 10px 14px;
    margin: 10px 0;
    font-size: 0.9em;
}
"""


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def _esc(text):
    return escape(str(text))


def _tag_row_html(tag_hex, keyword, vr, values):
    """Render a single tag with status indicator and values."""
    status = (
        '<span class="status-review">{} value(s)</span>'.format(len(values))
        if values
        else '<span class="status-clean">Empty / Clean</span>'
    )

    html = '<div class="tag-row">'
    html += '<div class="tag-header">'
    html += f'<span><span class="tag-label">({_esc(tag_hex)}) {_esc(keyword)}</span>'
    html += f'<span class="tag-vr">{_esc(vr)}</span></span>'
    html += status
    html += '</div>'

    if values:
        html += '<div class="values">'
        for v in values:
            html += f'<div>{_esc(v) if v.strip() else "&lt;empty&gt;"}</div>'
        html += '</div>'

    html += '</div>'
    return html


def _details(summary, content, open_default=False):
    """Wrap content in a collapsible <details> block."""
    open_attr = " open" if open_default else ""
    return f'<details{open_attr}><summary>{_esc(summary)}</summary><div class="content">{content}</div></details>'


# ---------------------------------------------------------------------------
# Section generators
# ---------------------------------------------------------------------------

def _section_overview(std_elements, priv_elements, sop_classes, studies, modalities, total_files, scan_summary=None):
    html = '<h2>Dataset Overview</h2>'
    html += '<div class="metrics">'
    for label, value in [
        ("DICOM Files Parsed", f"{total_files:,}"),
        ("Studies", str(len(studies))),
        ("Standard Tags", str(len(std_elements))),
        ("Private Element Groups", str(len(priv_elements))),
    ]:
        html += f'<div class="metric"><div class="value">{_esc(value)}</div><div class="label">{_esc(label)}</div></div>'
    html += '</div>'

    if scan_summary and scan_summary.get("total_files", 0) > 0:
        total = scan_summary["total_files"]
        parsed = scan_summary.get("dicom_parsed", 0)
        errors = scan_summary.get("parse_errors", 0)
        skipped = total - parsed - errors
        parts = [f"{total:,} files found in project"]
        if parsed:
            parts.append(f"{parsed:,} DICOM files parsed")
        if errors:
            parts.append(f"{errors:,} could not be parsed")
        if skipped:
            parts.append(f"{skipped:,} non-DICOM skipped")
        html += f'<p style="color:#888; font-size:0.9em;">{" &bull; ".join(parts)}</p>'

    html += '<h3>Modalities</h3>'
    if modalities:
        html += ', '.join(f'<code>{_esc(m)}</code>' for m in modalities)
    else:
        html += '<div class="info-box">No modality information found</div>'

    html += '<h3>SOP Classes</h3>'
    if sop_classes:
        html += ', '.join(f'<code>{_esc(s)}</code>' for s in sop_classes)
    else:
        html += '<div class="info-box">No SOP classes found</div>'

    return html


def _section_phi_review(std_elements, dt_elements):
    html = '<h2>PHI Review</h2>'

    for group_name, tags in PHI_GROUPS.items():
        content = ""
        for tag_hex, keyword in tags:
            elem = std_elements.get(tag_hex, {})
            values = elem.get("values", [])
            vr = elem.get("vr", "")
            content += _tag_row_html(tag_hex, keyword, vr, values)

        is_first = (group_name == "Patient Demographics")
        html += _details(group_name, content, open_default=is_first)

    # Dates & Times
    dt_content = ""
    if dt_elements:
        for tag_display, values in dt_elements.items():
            dt_content += f'<div class="tag-row"><span class="tag-label">{_esc(tag_display)}</span>'
            if values:
                display = [_esc(v) if v.strip() else "&lt;empty&gt;" for v in values]
                dt_content += f'<div class="values"><div>{", ".join(display)}</div></div>'
            else:
                dt_content += '<div class="values"><div>&lt;empty&gt;</div></div>'
            dt_content += '</div>'
    else:
        dt_content = '<div class="info-box">No date/time elements found</div>'
    html += _details("Dates & Times", dt_content)

    return html


def _section_tag_explorer(std_elements, priv_elements, std_sequences, priv_sequences):
    html = '<h2>Tag Explorer</h2>'

    # Standard elements
    std_content = ""
    for tag_hex, data in std_elements.items():
        std_content += _tag_row_html(tag_hex, data["keyword"], data["vr"], data["values"])
    html += _details(f"Standard Elements ({len(std_elements)})", std_content)

    # Private elements
    priv_content = ""
    for key, values in priv_elements.items():
        status = (
            f'<span class="status-review">{len(values)} value(s)</span>'
            if values
            else '<span class="status-clean">Empty</span>'
        )
        priv_content += f'<div class="tag-row"><div class="tag-header"><span class="tag-label">{_esc(key)}</span>{status}</div>'
        if values:
            priv_content += '<div class="values">'
            for v in values:
                priv_content += f'<div>{_esc(v) if v.strip() else "&lt;empty&gt;"}</div>'
            priv_content += '</div>'
        priv_content += '</div>'
    html += _details(f"Private Elements ({len(priv_elements)})", priv_content)

    # Sequences
    all_seq = {}
    for k, v in std_sequences.items():
        all_seq[f"[Std] {k}"] = v
    for k, v in priv_sequences.items():
        all_seq[f"[Priv] {k}"] = v

    seq_content = ""
    if all_seq:
        for key, values in all_seq.items():
            seq_content += f'<div class="tag-row"><span class="tag-label">{_esc(key)}</span>'
            if values:
                seq_content += '<div class="values">'
                for v in values:
                    seq_content += f'<div>{_esc(v) if v.strip() else "&lt;empty&gt;"}</div>'
                seq_content += '</div>'
            seq_content += '</div>'
    else:
        seq_content = '<div class="info-box">No sequence elements found</div>'
    html += _details(f"Sequences ({len(all_seq)})", seq_content)

    return html


def _section_study_summary(counts, large_priv):
    html = '<h2>Study Summary</h2>'

    if counts:
        html += '<div class="table-scroll"><table><tr><th>Study UID</th><th>Files</th><th>&gt;1KB</th><th>&gt;20KB</th><th>&gt;50KB</th></tr>'
        for r in counts:
            html += '<tr>'
            html += f'<td><code>{_esc(r["Study UID"])}</code></td>'
            html += f'<td>{_esc(r["Files"])}</td>'
            html += f'<td>{_esc(r[">1KB Private"])}</td>'
            html += f'<td>{_esc(r[">20KB Private"])}</td>'
            html += f'<td>{_esc(r[">50KB Private"])}</td>'
            html += '</tr>'
        html += '</table></div>'
        total = sum(int(r["Files"]) for r in counts)
        html += f'<div class="metrics"><div class="metric"><div class="value">{total:,}</div><div class="label">Total files</div></div></div>'
    else:
        html += '<div class="info-box">No study data found</div>'

    html += '<h3>Large Private Elements</h3>'
    if large_priv:
        html += '<div class="warning-box">Large private elements detected. These are SHA-256 hashes of private data elements exceeding size thresholds.</div>'
        total_hashes = len(large_priv)
        total_occurrences = sum(r["Count"] for r in large_priv)
        html += f'<div class="metrics"><div class="metric"><div class="value">{total_hashes:,}</div><div class="label">Unique hashes</div></div>'
        html += f'<div class="metric"><div class="value">{total_occurrences:,}</div><div class="label">Total occurrences</div></div></div>'
        sorted_priv = sorted(large_priv, key=lambda r: r["Count"], reverse=True)
        display_limit = 10
        html += '<div class="table-scroll"><table><tr><th>SHA-256 Hash</th><th>Occurrences</th></tr>'
        for r in sorted_priv[:display_limit]:
            html += f'<tr><td><code>{_esc(r["Hash"])}</code></td><td>{_esc(r["Count"])}</td></tr>'
        html += '</table></div>'
        if total_hashes > display_limit:
            html += f'<p><em>Showing top {display_limit} of {total_hashes:,} unique hashes. Full data available in large_private_elements.txt</em></p>'
    else:
        html += '<div class="success-box">No large private elements detected</div>'

    return html


def _section_private_creators(creators):
    html = '<h2>Private Creators</h2>'

    if creators:
        html += '<div class="table-scroll"><table><tr><th>Tag</th><th>Creator ID</th></tr>'
        for c in creators:
            html += f'<tr><td><code>{_esc(c["Tag"])}</code></td><td>{_esc(c["Creator ID"])}</td></tr>'
        html += '</table></div>'
    else:
        html += '<div class="info-box">No private creators found</div>'

    return html


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_html_report(output_dir, project_name=""):
    """Generate a complete standalone HTML report.

    Args:
        output_dir: Path to tag sniffer output directory.
        project_name: Project name for the header.

    Returns:
        Complete HTML document as a string.
    """
    # Parse all data
    std_path = os.path.join(output_dir, "standard_elements.txt")
    priv_path = os.path.join(output_dir, "private_elements.txt")
    dt_path = os.path.join(output_dir, "date_time_elements.txt")
    sop_path = os.path.join(output_dir, "sop_classes.txt")
    studies_path = os.path.join(output_dir, "dicom_studies.txt")
    counts_path = os.path.join(output_dir, "counts.txt")
    creators_path = os.path.join(output_dir, "private_creators.txt")
    std_seq_path = os.path.join(output_dir, "standard_sequences.txt")
    priv_seq_path = os.path.join(output_dir, "private_sequences.txt")
    large_priv_path = os.path.join(output_dir, "large_private_elements.txt")

    std_elements = parse_standard_elements(std_path) if os.path.exists(std_path) else {}
    priv_elements = parse_private_elements(priv_path) if os.path.exists(priv_path) else {}
    dt_elements = parse_date_time(dt_path) if os.path.exists(dt_path) else {}
    sop_classes = parse_simple_list(sop_path)
    studies = parse_simple_list(studies_path)
    counts = parse_counts(counts_path)
    creators = parse_private_creators(creators_path)
    std_sequences = parse_sequences(std_seq_path)
    priv_sequences = parse_sequences(priv_seq_path)
    large_priv = parse_large_private_elements(large_priv_path)
    summary_path = os.path.join(output_dir, "scan_summary.txt")
    scan_summary = parse_scan_summary(summary_path)

    total_files = sum(int(r["Files"]) for r in counts) if counts else 0
    modalities = std_elements.get("0008,0060", {}).get("values", [])

    # Build HTML
    title = f"PHI Report — {project_name}" if project_name else "PHI Report"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    body = f'<h1>{_esc(title)}</h1>'
    body += '<div class="header-info">'
    body += f'<span><strong>Generated:</strong> {_esc(timestamp)}</span>'
    if project_name:
        body += f'<span><strong>Project:</strong> {_esc(project_name)}</span>'
    body += f'<span><strong>DICOM files parsed:</strong> {total_files:,}</span>'
    body += '</div>'

    body += _section_overview(std_elements, priv_elements, sop_classes, studies, modalities, total_files, scan_summary)
    body += '<div class="section-divider"></div>'
    body += _section_phi_review(std_elements, dt_elements)
    body += '<div class="section-divider"></div>'
    body += _section_tag_explorer(std_elements, priv_elements, std_sequences, priv_sequences)
    body += '<div class="section-divider"></div>'
    body += _section_study_summary(counts, large_priv)
    body += '<div class="section-divider"></div>'
    body += _section_private_creators(creators)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(title)}</title>
<style>
{_CSS}
</style>
</head>
<body>
{body}
</body>
</html>"""

    return html
