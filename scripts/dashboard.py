"""
DICOM Tag Sniffer — PHI Review Dashboard

Usage:
    streamlit run scripts/dashboard.py -- /path/to/output-dir
"""

import os
import re
import sys
import streamlit as st
from collections import OrderedDict


# ---------------------------------------------------------------------------
# Parsing functions (cached)
# ---------------------------------------------------------------------------

@st.cache_data
def parse_standard_elements(filepath):
    """Parse standard_elements.txt into an ordered dict of tag_hex -> {vr, keyword, values}."""
    elements = OrderedDict()
    tag_list = []

    with open(filepath, "r") as f:
        lines = f.readlines()

    # Phase 1: parse the tag listing at the top
    in_listing = False
    for line in lines:
        line = line.rstrip("\n")
        if line == "List of Standard Elements":
            in_listing = True
            continue
        if in_listing:
            m = re.match(r"^\((\w{4},\w{4})\)\s+(\w+)\s+(.+)$", line)
            if m:
                tag_hex, vr, keyword = m.group(1), m.group(2), m.group(3)
                tag_list.append((tag_hex, vr, keyword))
                elements[tag_hex] = {"vr": vr, "keyword": keyword, "values": []}
            elif line.strip() == "":
                if tag_list:
                    in_listing = False
            continue

    # Phase 2: parse the values sections
    current_tag = None
    for line in lines:
        line = line.rstrip("\n")
        m = re.match(r"^\((\w{4},\w{4})\)\s+(\w+)\s+(.+)$", line)
        if m:
            tag_hex = m.group(1)
            if tag_hex in elements:
                current_tag = tag_hex
            else:
                current_tag = None
            continue
        if current_tag and line.startswith("  "):
            elements[current_tag]["values"].append(line.strip())
        elif line.strip() == "":
            pass  # blank line between sections

    return elements


@st.cache_data
def parse_private_elements(filepath):
    """Parse private_elements.txt into an ordered dict of key -> list of values."""
    elements = OrderedDict()

    with open(filepath, "r") as f:
        lines = f.readlines()

    # Find the blank line that separates the key listing from the values section.
    # Format: header lines, then key listing (non-blank, non-indented), then a
    # blank line, then repeated (key header + indented values + blank line).
    sep_idx = None
    for i, raw in enumerate(lines):
        stripped = raw.strip()
        # Skip the first two header lines and any leading blanks
        if stripped in ("Private Elements", "List of Element Keys", ""):
            if stripped == "" and i > 2:
                # First blank line after key listing starts the values section
                sep_idx = i
                break
            continue
        # We're in the key listing; keep going
        continue

    if sep_idx is None:
        return elements

    # Parse values section (everything after the separator blank line)
    current_key = None
    for raw in lines[sep_idx + 1:]:
        line = raw.rstrip("\n")
        if line.strip() == "":
            continue
        if not line.startswith("  "):
            current_key = line.strip()
            if current_key not in elements:
                elements[current_key] = []
        elif current_key:
            elements[current_key].append(line.strip())

    return elements


@st.cache_data
def parse_sequences(filepath):
    """Parse standard_sequences.txt or private_sequences.txt."""
    sequences = OrderedDict()

    if not os.path.exists(filepath):
        return sequences

    with open(filepath, "r") as f:
        lines = f.readlines()

    current_key = None
    for line in lines:
        line = line.rstrip("\n")
        if line.startswith("Standard Sequence") or line.startswith("Private Sequence") or line.strip() == "":
            if line.strip() == "" and current_key:
                pass
            continue
        if line.startswith("  "):
            if current_key:
                sequences[current_key].append(line.strip())
        else:
            current_key = line.strip()
            if current_key not in sequences:
                sequences[current_key] = []

    return sequences


@st.cache_data
def parse_date_time(filepath):
    """Parse date_time_elements.txt."""
    elements = OrderedDict()

    with open(filepath, "r") as f:
        lines = f.readlines()

    current_key = None
    for line in lines:
        line = line.rstrip("\n")
        if line == "Date/Time Elements" or line.strip() == "":
            continue
        m = re.match(r"^\((\w{4},\w{4})\)\s+(\w+)\s+(.+)$", line)
        if m:
            tag_hex, vr, keyword = m.group(1), m.group(2), m.group(3)
            current_key = f"({tag_hex}) {vr} {keyword}"
            elements[current_key] = []
            continue
        if current_key and line.startswith("  "):
            elements[current_key].append(line.strip())

    return elements


@st.cache_data
def parse_simple_list(filepath):
    """Parse a file that is a header line followed by one value per line."""
    items = []
    if not os.path.exists(filepath):
        return items
    with open(filepath, "r") as f:
        lines = f.readlines()
    for line in lines[1:]:  # skip header
        val = line.strip()
        if val:
            items.append(val)
    return items


@st.cache_data
def parse_counts(filepath):
    """Parse counts.txt into a list of dicts."""
    rows = []
    if not os.path.exists(filepath):
        return rows
    with open(filepath, "r") as f:
        lines = f.readlines()
    for line in lines[1:]:  # skip header
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 6:
            rows.append({
                "Study UID": parts[0],
                "Files": parts[2],
                ">1KB Private": parts[3],
                ">20KB Private": parts[4],
                ">50KB Private": parts[5],
            })
    return rows


@st.cache_data
def parse_private_creators(filepath):
    """Parse private_creators.txt."""
    creators = []
    if not os.path.exists(filepath):
        return creators
    with open(filepath, "r") as f:
        lines = f.readlines()
    for line in lines:
        line = line.strip()
        if line and line != "Private Creators" and line != "":
            parts = line.split("\t", 1)
            if len(parts) == 2:
                creators.append({"Tag": parts[0], "Creator ID": parts[1]})
    return creators


@st.cache_data
def parse_large_private_elements(filepath):
    """Parse large_private_elements.txt into a list of dicts."""
    rows = []
    if not os.path.exists(filepath):
        return rows
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("Hash: "):
                # Format: "Hash: <hex>, count: <N>"
                parts = line.split(", count: ", 1)
                if len(parts) == 2:
                    rows.append({
                        "Hash": parts[0][6:],  # strip "Hash: "
                        "Count": int(parts[1]),
                    })
    return rows


# ---------------------------------------------------------------------------
# PHI tag definitions
# ---------------------------------------------------------------------------

PHI_GROUPS = OrderedDict([
    ("Patient Demographics", [
        ("0010,0010", "PatientName"),
        ("0010,0020", "PatientID"),
        ("0010,0030", "PatientBirthDate"),
        ("0010,0040", "PatientSex"),
        ("0010,1010", "PatientAge"),
        ("0010,1020", "PatientSize"),
        ("0010,1030", "PatientWeight"),
    ]),
    ("Institutional / Referring", [
        ("0008,0080", "InstitutionName"),
        ("0008,0090", "ReferringPhysicianName"),
        ("0008,1010", "StationName"),
        ("0008,0050", "AccessionNumber"),
    ]),
    ("Descriptions (may contain PHI)", [
        ("0008,1030", "StudyDescription"),
        ("0008,103E", "SeriesDescription"),
        ("0008,1080", "AdmittingDiagnosesDescription"),
        ("0010,21B0", "AdditionalPatientHistory"),
    ]),
    ("De-identification Status", [
        ("0012,0062", "PatientIdentityRemoved"),
        ("0012,0063", "DeidentificationMethod"),
    ]),
    ("UIDs", [
        ("0008,0018", "SOPInstanceUID"),
        ("0020,000D", "StudyInstanceUID"),
        ("0020,000E", "SeriesInstanceUID"),
        ("0020,0052", "FrameOfReferenceUID"),
        ("0002,0003", "MediaStorageSOPInstanceUID"),
        ("0008,0014", "InstanceCreatorUID"),
    ]),
    ("Equipment / Protocol", [
        ("0008,0070", "Manufacturer"),
        ("0008,1090", "ManufacturerModelName"),
        ("0018,1000", "DeviceSerialNumber"),
        ("0018,1020", "SoftwareVersions"),
        ("0018,1030", "ProtocolName"),
        ("0002,0016", "SourceApplicationEntityTitle"),
        ("0040,0241", "PerformedStationAETitle"),
    ]),
    ("Procedure Info", [
        ("0020,0010", "StudyID"),
        ("0032,1060", "RequestedProcedureDescription"),
        ("0040,0254", "PerformedProcedureStepDescription"),
        ("0020,4000", "ImageComments"),
        ("0010,21C0", "PregnancyStatus"),
    ]),
])


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

def main():
    st.set_page_config(
        page_title="DICOM Tag Sniffer — PHI Review",
        page_icon=":hospital:",
        layout="wide",
    )

    st.title("DICOM Tag Sniffer - PHI Review Dashboard", anchor=False)

    # Determine output directory
    default_dir = ""
    if len(sys.argv) > 1:
        default_dir = sys.argv[1]

    with st.sidebar:
        st.header("Settings", anchor=False)
        report_dir = st.text_input("Report output directory", value=default_dir)
        st.divider()
        section = st.radio(
            "Section",
            ["Dataset Overview", "PHI Review", "Tag Explorer", "Study Summary", "Private Creators"],
            index=0,
        )

    if not report_dir or not os.path.isdir(report_dir):
        st.warning("Please enter a valid report output directory in the sidebar.")
        return

    # Load data
    std_path = os.path.join(report_dir, "standard_elements.txt")
    priv_path = os.path.join(report_dir, "private_elements.txt")
    dt_path = os.path.join(report_dir, "date_time_elements.txt")
    sop_path = os.path.join(report_dir, "sop_classes.txt")
    studies_path = os.path.join(report_dir, "dicom_studies.txt")
    counts_path = os.path.join(report_dir, "counts.txt")
    creators_path = os.path.join(report_dir, "private_creators.txt")
    std_seq_path = os.path.join(report_dir, "standard_sequences.txt")
    priv_seq_path = os.path.join(report_dir, "private_sequences.txt")
    large_priv_path = os.path.join(report_dir, "large_private_elements.txt")

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

    # Compute total files
    total_files = sum(int(r["Files"]) for r in counts) if counts else 0

    # Get modalities
    modalities = std_elements.get("0008,0060", {}).get("values", [])

    # -----------------------------------------------------------------------
    if section == "Dataset Overview":
        render_overview(std_elements, priv_elements, sop_classes, studies, modalities, total_files)
    elif section == "PHI Review":
        render_phi_review(std_elements, dt_elements)
    elif section == "Tag Explorer":
        render_tag_explorer(std_elements, priv_elements, std_sequences, priv_sequences)
    elif section == "Study Summary":
        render_study_summary(counts, large_priv)
    elif section == "Private Creators":
        render_private_creators(creators)


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def render_overview(std_elements, priv_elements, sop_classes, studies, modalities, total_files, files_scanned=None):
    st.header("Dataset Overview", anchor=False)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("DICOM Files Parsed", f"{total_files:,}")
    c2.metric("Studies", len(studies))
    c3.metric("Standard Tags", len(std_elements))
    c4.metric("Private Element Groups", len(priv_elements))

    if files_scanned and files_scanned != total_files:
        st.caption(
            f"{files_scanned:,} files were found in the directory. "
            f"{total_files:,} were successfully parsed as valid DICOM. "
            f"The remaining {files_scanned - total_files:,} may be non-DICOM files "
            f"(e.g. DICOMDIR, thumbnails) or files that failed to parse."
        )

    st.divider()

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Modalities", anchor=False)
        if modalities:
            st.markdown("\n".join(f"- `{m}`" for m in modalities))
        else:
            st.info("No modality information found")

    with col2:
        st.subheader("SOP Classes", anchor=False)
        if sop_classes:
            st.markdown("\n".join(f"- `{s}`" for s in sop_classes))
        else:
            st.info("No SOP classes found")


def render_phi_review(std_elements, dt_elements):
    st.header("PHI Review", anchor=False)
    st.caption("Tags most relevant for Protected Health Information review. Expand each group to see unique values found across the dataset.")

    for group_name, tags in PHI_GROUPS.items():
        with st.expander(group_name, expanded=(group_name == "Patient Demographics")):
            for tag_hex, keyword in tags:
                elem = std_elements.get(tag_hex, {})
                values = elem.get("values", [])
                vr = elem.get("vr", "")

                col_label, col_status = st.columns([3, 1])
                with col_label:
                    st.markdown(f"**`({tag_hex})` {keyword}** `{vr}`")
                with col_status:
                    if not values:
                        st.success("Empty / Clean")
                    else:
                        st.warning(f"{len(values)} value(s)")
                if values:
                    display_lines = [v if v.strip() else "<empty>" for v in values]
                    height = min(200, 30 * len(display_lines) + 40)
                    with st.container(border=True, height=height):
                        st.code("\n".join(display_lines), language=None)

    # Dates section
    with st.expander("Dates & Times"):
        if dt_elements:
            for tag_display, values in dt_elements.items():
                st.markdown(f"**{tag_display}**")
                if values:
                    display = [v if v.strip() else "<empty>" for v in values]
                    height = min(200, 30 * len(display) + 40)
                    with st.container(border=True, height=height):
                        st.code(", ".join(display), language=None)
                else:
                    st.caption("<empty>")
        else:
            st.info("No date/time elements found")



def _render_tag_values(values, key_suffix=""):
    """Render tag values as a dataframe for many values, or code block for few."""
    if not values:
        st.info("No values recorded")
        return
    display = [v if v.strip() else "<empty>" for v in values]
    if len(display) > 5:
        import pandas as pd
        df = pd.DataFrame({"Value": display})
        st.dataframe(df, use_container_width=True, hide_index=True, key=f"values_df_{key_suffix}")
    else:
        st.code("\n".join(display), language=None)


def render_tag_explorer(std_elements, priv_elements, std_sequences, priv_sequences):
    st.header("Tag Explorer", anchor=False)

    tab_std, tab_priv, tab_seq = st.tabs(["Standard Elements", "Private Elements", "Sequences"])

    with tab_std:
        if not std_elements:
            st.info("No standard elements found")
            return

        options = [
            f"({tag}) {data['vr']} {data['keyword']}"
            for tag, data in std_elements.items()
        ]
        tag_keys = list(std_elements.keys())

        selected = st.selectbox("Select a standard tag", options, index=0, key="std_tag_select")
        if selected:
            idx = options.index(selected)
            tag_hex = tag_keys[idx]
            data = std_elements[tag_hex]
            st.subheader(f"({tag_hex}) {data['keyword']}", anchor=False)
            st.caption(f"VR: {data['vr']}  |  {len(data['values'])} unique value(s)")
            _render_tag_values(data["values"], key_suffix=f"std_{tag_hex}")

    with tab_priv:
        if not priv_elements:
            st.info("No private elements found")
            return

        priv_keys = list(priv_elements.keys())
        selected_priv = st.selectbox("Select a private element", priv_keys, index=0, key="priv_tag_select")
        if selected_priv:
            values = priv_elements[selected_priv]
            st.subheader(selected_priv, anchor=False)
            st.caption(f"{len(values)} unique value(s)")
            _render_tag_values(values, key_suffix=f"priv_{selected_priv}")

    with tab_seq:
        all_seq = OrderedDict()
        for k, v in std_sequences.items():
            all_seq[f"[Std] {k}"] = v
        for k, v in priv_sequences.items():
            all_seq[f"[Priv] {k}"] = v

        if not all_seq:
            st.info("No sequence elements found")
            return

        seq_keys = list(all_seq.keys())
        selected_seq = st.selectbox("Select a sequence element", seq_keys, index=0, key="seq_select")
        if selected_seq:
            values = all_seq[selected_seq]
            st.subheader(selected_seq, anchor=False)
            st.caption(f"{len(values)} unique value(s)")
            _render_tag_values(values, key_suffix=f"seq_{selected_seq}")


def render_study_summary(counts, large_priv):
    st.header("Study Summary", anchor=False)

    if not counts:
        st.info("No study data found")
        return

    total = sum(int(r["Files"]) for r in counts)
    c1, c2 = st.columns(2)
    c1.metric("Total Files", f"{total:,}")
    c2.metric("Studies", len(counts))

    st.dataframe(
        counts,
        use_container_width=True,
        column_config={
            "Study UID": st.column_config.TextColumn("Study UID", width="large"),
            "Files": st.column_config.NumberColumn("Files"),
            ">1KB Private": st.column_config.NumberColumn(">1KB"),
            ">20KB Private": st.column_config.NumberColumn(">20KB"),
            ">50KB Private": st.column_config.NumberColumn(">50KB"),
        },
    )

    st.divider()
    st.subheader("Large Private Elements", anchor=False)
    if large_priv:
        st.warning(
            "Large private elements detected. These are SHA-256 hashes of private "
            "data elements exceeding size thresholds, which may indicate embedded "
            "images or hidden PHI."
        )
        st.dataframe(
            large_priv,
            use_container_width=True,
            column_config={
                "Hash": st.column_config.TextColumn("SHA-256 Hash", width="large"),
                "Count": st.column_config.NumberColumn("Occurrences"),
            },
        )
    else:
        st.success("No large private elements detected")


def render_private_creators(creators):
    st.header("Private Creators", anchor=False)
    st.caption("Vendor-specific private creator IDs found in the dataset")

    if not creators:
        st.info("No private creators found")
        return

    # Summary metrics
    unique_creators = set(c["Creator ID"] for c in creators)
    c1, c2 = st.columns(2)
    c1.metric("Total Creator Tags", len(creators))
    c2.metric("Unique Vendors", len(unique_creators))

    st.divider()
    st.dataframe(
        creators,
        use_container_width=True,
        column_config={
            "Tag": st.column_config.TextColumn("Tag", width="small"),
            "Creator ID": st.column_config.TextColumn("Creator ID", width="large"),
        },
    )


if __name__ == "__main__":
    main()
