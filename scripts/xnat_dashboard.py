"""
DICOM Tag Sniffer — XNAT JupyterHub Dashboard

Launches from an XNAT project via JupyterHub. Three states:
  1. Startup  — shows project info, "Run PHI Detection" button
  2. Running  — progress bar while tag sniffer executes
  3. Dashboard — full PHI review dashboard + HTML report download

Usage (XNAT):
    Registered as a Streamlit dashboard in XNAT admin.
    XNAT sets env vars: XNAT_HOST, XNAT_USER, XNAT_PASS, XNAT_ITEM_ID,
                        XNAT_XSI_TYPE, XNAT_DATA

Usage (local testing):
    streamlit run scripts/xnat_dashboard.py
"""

import os
import subprocess
import sys

# ---------------------------------------------------------------------------
# Auto-install dependencies from requirements-xnat.txt before anything else
# ---------------------------------------------------------------------------
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_REQUIREMENTS = os.path.join(_SCRIPT_DIR, "requirements-xnat.txt")

if os.path.isfile(_REQUIREMENTS):
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "-q", "-r", _REQUIREMENTS],
        stdout=subprocess.DEVNULL,
    )

# Point Streamlit at the .streamlit config dir bundled with this script
# (must be set before importing streamlit)
os.environ.setdefault("STREAMLIT_CONFIG_DIR", os.path.join(_SCRIPT_DIR, ".streamlit"))

import atexit
import shutil
import tempfile
import time

import streamlit as st

# ---------------------------------------------------------------------------
# Locate bundled resources relative to this script
# ---------------------------------------------------------------------------
_RESOURCES_DIR = os.path.join(_SCRIPT_DIR, "resources")
_DEFAULT_JAR = os.path.join(_RESOURCES_DIR, "tagsniffer.jar")
_DEFAULT_RULES = os.path.join(_RESOURCES_DIR, "simple_rules.xml")
_COMPREHENSIVE_RULES = os.path.join(_RESOURCES_DIR, "example_rules.xml")

# Rules options for startup screen (label -> path)
_RULES_OPTIONS = {
    "Simple (5 rules) — minimal noise reduction, shows more raw values": _DEFAULT_RULES,
    "Comprehensive (20 rules) — aggressive date/value consolidation": _COMPREHENSIVE_RULES,
}

# ---------------------------------------------------------------------------
# Import rendering functions from the core dashboard
# ---------------------------------------------------------------------------
sys.path.insert(0, _SCRIPT_DIR)
from dashboard import (
    parse_standard_elements,
    parse_private_elements,
    parse_sequences,
    parse_date_time,
    parse_simple_list,
    parse_counts,
    parse_private_creators,
    parse_large_private_elements,
    render_overview,
    render_phi_review,
    render_tag_explorer,
    render_study_summary,
    render_private_creators,
    PHI_GROUPS,
)
from html_report import generate_html_report


# ---------------------------------------------------------------------------
# Java detection and auto-install
# ---------------------------------------------------------------------------

def _set_java_env(java_home):
    """Set JAVA_HOME and update PATH for a given JDK directory."""
    os.environ["JAVA_HOME"] = java_home
    java_bin = os.path.join(java_home, "bin")
    if java_bin not in os.environ.get("PATH", ""):
        os.environ["PATH"] = java_bin + os.pathsep + os.environ.get("PATH", "")


def _check_jdk_dir(jdk_dir):
    """Check if a JDK is already installed in the given directory."""
    if os.path.isdir(jdk_dir):
        for entry in os.listdir(jdk_dir):
            candidate = os.path.join(jdk_dir, entry, "bin", "java")
            if os.path.isfile(candidate):
                _set_java_env(os.path.join(jdk_dir, entry))
                return candidate
    return None


def _install_jdk(jdk_dir):
    """Install JDK 17 via install-jdk package to the given directory."""
    try:
        import jdk
    except ImportError:
        st.error(
            "Java not found and `install-jdk` package not available. "
            "Install Java manually or run: `pip install install-jdk`"
        )
        return None

    with st.spinner("Java not found. Installing JDK 17 (one-time download, ~180MB)..."):
        installed_path = jdk.install("17", path=jdk_dir)
        java_candidate = os.path.join(installed_path, "bin", "java")
        if os.path.isfile(java_candidate):
            _set_java_env(installed_path)
            return java_candidate
    return None


def ensure_java():
    """Ensure Java is available.

    XNAT mode (JUPYTERHUB_ROOT_DIR is set):
        Check {JUPYTERHUB_ROOT_DIR}/.jdk/ for existing install,
        otherwise download JDK 17 via install-jdk to that location.

    Local mode (JUPYTERHUB_ROOT_DIR not set):
        Check PATH, probe common OS locations, fall back to ~/.jdk/.
    """
    jupyterhub_root = os.environ.get("JUPYTERHUB_ROOT_DIR")

    if jupyterhub_root:
        # --- XNAT mode ---
        jdk_dir = os.path.join(jupyterhub_root, ".jdk")
        found = _check_jdk_dir(jdk_dir)
        if found:
            return found
        return _install_jdk(jdk_dir)

    else:
        # --- Local mode ---
        # 1. Check PATH
        java_path = shutil.which("java")
        if java_path:
            try:
                result = subprocess.run([java_path, "-version"], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    return java_path
            except Exception:
                pass

        # 2. Probe common OS locations
        for candidate_home in [
            "/opt/homebrew/opt/openjdk",       # macOS Homebrew
            "/usr/lib/jvm/default-java",       # Debian/Ubuntu
            "/usr/lib/jvm/java",               # RHEL/CentOS
            "/usr/local/openjdk",              # Docker images
        ]:
            candidate = os.path.join(candidate_home, "bin", "java")
            if os.path.isfile(candidate):
                _set_java_env(candidate_home)
                return candidate

        # 3. Check ~/.jdk/ for previously installed JDK
        jdk_dir = os.path.join(os.path.expanduser("~"), ".jdk")
        found = _check_jdk_dir(jdk_dir)
        if found:
            return found

        # 4. Install as last resort
        return _install_jdk(jdk_dir)


# ---------------------------------------------------------------------------
# Tag sniffer execution
# ---------------------------------------------------------------------------

def run_tag_sniffer(input_dir, output_dir, jar_path, rules_path, java_path):
    """Run the tag sniffer JAR and yield progress lines."""
    env = os.environ.copy()

    cmd = [
        java_path, "-jar", jar_path,
        "0",  # command: collect unique values, no counts
        input_dir,
        output_dir,
        rules_path,
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
    )

    last_lines = []
    for line in proc.stdout:
        stripped = line.rstrip("\n")
        last_lines.append(stripped)
        if len(last_lines) > 20:
            last_lines.pop(0)
        yield stripped

    proc.wait()
    if proc.returncode != 0:
        tail = "\n".join(last_lines[-10:])
        raise RuntimeError(
            f"Tag sniffer exited with code {proc.returncode}\n\n"
            f"Last output:\n{tail}"
        )


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------

def _cleanup_temp_dir():
    """Remove temp output directory containing PHI data on process exit."""
    output_dir = getattr(st.session_state, "output_dir", None) if hasattr(st, "session_state") else None
    if output_dir and os.path.isdir(output_dir):
        shutil.rmtree(output_dir, ignore_errors=True)


atexit.register(_cleanup_temp_dir)


def init_state():
    """Initialize session state on first run."""
    if "state" not in st.session_state:
        st.session_state.state = "startup"
    if "output_dir" not in st.session_state:
        st.session_state.output_dir = None
    if "input_dir" not in st.session_state:
        st.session_state.input_dir = None
    if "project_name" not in st.session_state:
        st.session_state.project_name = ""


# ---------------------------------------------------------------------------
# Startup screen
# ---------------------------------------------------------------------------

def render_startup():
    """Show welcome screen with project info and run button."""
    xnat_host = os.environ.get("XNAT_HOST", "")
    xnat_item = os.environ.get("XNAT_ITEM_ID", "")
    st.title("DICOM Tag Sniffer - PHI Detection", anchor=False)
    st.caption("Scan DICOM files in this project for Protected Health Information.")

    st.divider()

    # Show XNAT context if available
    if xnat_host:
        c1, c2 = st.columns(2)
        c1.markdown(f"**XNAT Host:** `{xnat_host}`")
        c2.markdown(f"**Project:** `{xnat_item}`")

    # Determine input directory
    # On XNAT, data is always at /data/projects/{XNAT_ITEM_ID}.
    # The tag sniffer recursively finds all DICOMs under the given directory.
    if xnat_item:
        input_dir = os.path.join("/data", "projects", xnat_item)
        st.info(f"DICOM data path: `{input_dir}`")
    else:
        st.warning("XNAT data mount not detected. Enter a path manually for local testing.")
        input_dir = st.text_input("Path to DICOM files", key="dicom_path_input").strip()

    if not input_dir or not os.path.isdir(input_dir):
        st.caption("Waiting for a valid DICOM directory...")
        return

    # Rules selection
    rules_label = st.selectbox(
        "Scan rules",
        options=list(_RULES_OPTIONS.keys()),
        index=0,
        help=(
            "Rules are display transforms that consolidate high-cardinality values "
            "(dates, times, floats) into human-readable summaries. They do not change "
            "which tags are extracted — only how values are displayed. "
            "Simple shows more raw values; Comprehensive collapses dates across many tags."
        ),
    )

    st.divider()

    # Run button
    if st.button("Run PHI Detection on this Project", type="primary", use_container_width=True):
        st.session_state.input_dir = input_dir
        st.session_state.project_name = xnat_item or os.path.basename(input_dir)
        st.session_state.output_dir = tempfile.mkdtemp(prefix="tagsniffer_")
        st.session_state.rules_path = _RULES_OPTIONS[rules_label]
        st.session_state.state = "running"
        st.rerun()


# ---------------------------------------------------------------------------
# Running screen
# ---------------------------------------------------------------------------

def render_running():
    """Run the tag sniffer with progress feedback."""
    input_dir = st.session_state.input_dir
    output_dir = st.session_state.output_dir

    st.header("Running PHI Detection...", anchor=False)

    # Check Java
    java_path = ensure_java()
    if not java_path:
        st.error(
            "Java is required but could not be found or installed.\n\n"
            "To fix this, add Java to the container image:\n"
            "```\napt-get install -y default-jre-headless\n```\n"
            "Or install via conda:\n"
            "```\nconda install -c conda-forge openjdk\n```"
        )
        if st.button("Back to Start"):
            st.session_state.state = "startup"
            st.rerun()
        return

    # Check JAR and rules
    rules_path = st.session_state.get("rules_path", _DEFAULT_RULES)
    if not os.path.isfile(_DEFAULT_JAR):
        st.error(f"Tag sniffer JAR not found at: `{_DEFAULT_JAR}`")
        return
    if not os.path.isfile(rules_path):
        st.error(f"Scan rules not found at: `{rules_path}`")
        return

    # Create output subdirectories
    os.makedirs(os.path.join(output_dir, "standard"), exist_ok=True)
    os.makedirs(os.path.join(output_dir, "private"), exist_ok=True)

    # Run with progress
    status = st.status("Scanning DICOM files...", expanded=True)
    progress_bar = st.progress(0, text="Starting...")
    log_area = st.empty()

    files_processed = 0
    last_log = ""

    try:
        for line in run_tag_sniffer(input_dir, output_dir, _DEFAULT_JAR, rules_path, java_path):
            last_log = line

            # Parse progress from tool output (logs every 1000 files)
            if "files processed" in line.lower() or "processed" in line.lower():
                try:
                    # Try to extract number from log line
                    parts = line.split()
                    for p in parts:
                        if p.isdigit():
                            files_processed = int(p)
                            break
                except (ValueError, IndexError):
                    pass

            log_area.code(last_log, language=None)

        progress_bar.progress(100, text="Complete!")
        status.update(label="Scan complete!", state="complete")

    except Exception as e:
        status.update(label="Scan failed", state="error")
        st.error(f"Error: {e}")
        if st.button("Back to Start"):
            st.session_state.state = "startup"
            st.rerun()
        return

    # Verify output was created
    std_file = os.path.join(output_dir, "standard_elements.txt")
    if not os.path.isfile(std_file):
        st.error("Tag sniffer completed but no output files were generated.")
        if st.button("Back to Start"):
            st.session_state.state = "startup"
            st.rerun()
        return

    time.sleep(1)  # Brief pause so user sees completion
    st.session_state.state = "dashboard"
    st.rerun()


# ---------------------------------------------------------------------------
# Dashboard screen (reuses existing dashboard.py renderers)
# ---------------------------------------------------------------------------

def _load_data(output_dir):
    """Load and cache all parsed data once into session state."""
    if "parsed_data" in st.session_state:
        return st.session_state.parsed_data

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

    data = {
        "std_elements": parse_standard_elements(std_path) if os.path.exists(std_path) else {},
        "priv_elements": parse_private_elements(priv_path) if os.path.exists(priv_path) else {},
        "dt_elements": parse_date_time(dt_path) if os.path.exists(dt_path) else {},
        "sop_classes": parse_simple_list(sop_path),
        "studies": parse_simple_list(studies_path),
        "counts": parse_counts(counts_path),
        "creators": parse_private_creators(creators_path),
        "std_sequences": parse_sequences(std_seq_path),
        "priv_sequences": parse_sequences(priv_seq_path),
        "large_priv": parse_large_private_elements(large_priv_path),
    }
    data["total_files"] = sum(int(r["Files"]) for r in data["counts"]) if data["counts"] else 0
    data["modalities"] = data["std_elements"].get("0008,0060", {}).get("values", [])

    st.session_state.parsed_data = data
    return data


def render_dashboard():
    """Full dashboard with HTML report download."""
    output_dir = st.session_state.output_dir
    project_name = st.session_state.project_name

    st.header(f"PHI Review - {project_name}", anchor=False)

    # Load all data once — cached in session state
    d = _load_data(output_dir)

    # Generate HTML report once — cached in session state
    if "html_report" not in st.session_state:
        st.session_state.html_report = generate_html_report(output_dir, project_name)

    # Sidebar navigation
    with st.sidebar:
        st.header("Navigation")
        section = st.radio(
            "Section",
            ["Dataset Overview", "PHI Review", "Tag Explorer", "Study Summary", "Private Creators"],
            index=0,
        )
        st.divider()
        st.download_button(
            label="Download HTML Report",
            data=st.session_state.html_report,
            file_name=f"phi_report_{project_name}.html",
            mime="text/html",
            use_container_width=True,
        )
        if st.button("Run New Scan", use_container_width=True):
            # Clean up previous temp dir before starting fresh
            if st.session_state.output_dir and os.path.isdir(st.session_state.output_dir):
                shutil.rmtree(st.session_state.output_dir, ignore_errors=True)
            # Clear cached data and report
            st.session_state.pop("parsed_data", None)
            st.session_state.pop("html_report", None)
            st.session_state.state = "startup"
            st.rerun()

    # Route to section renderer
    if section == "Dataset Overview":
        render_overview(d["std_elements"], d["priv_elements"], d["sop_classes"], d["studies"], d["modalities"], d["total_files"])
    elif section == "PHI Review":
        render_phi_review(d["std_elements"], d["dt_elements"])
    elif section == "Tag Explorer":
        render_tag_explorer(d["std_elements"], d["priv_elements"], d["std_sequences"], d["priv_sequences"])
    elif section == "Study Summary":
        render_study_summary(d["counts"], d["large_priv"])
    elif section == "Private Creators":
        render_private_creators(d["creators"])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

_CUSTOM_CSS = """
<style>
    /* Primary button — muted steel blue */
    .stButton > button[kind="primary"] {
        background-color: #7BA7CC;
        border-color: #7BA7CC;
    }
    /* Metric cards — orange top border */
    [data-testid="stMetric"] {
        border-top: 3px solid #FF702A;
        padding-top: 10px;
    }
    /* Tab underline — blue */
    button[data-baseweb="tab"][aria-selected="true"] {
        border-bottom-color: #2C82FD !important;
    }
    /* Progress bar — blue */
    .stProgress > div > div > div {
        background-color: #2C82FD !important;
    }
    /* Expander header hover — subtle amber */
    .streamlit-expanderHeader:hover {
        color: #FF702A !important;
    }
    /* Download button — blue outline */
    .stDownloadButton > button {
        border-color: #2C82FD;
        color: #2C82FD;
    }
    .stDownloadButton > button:hover {
        background-color: #2C82FD;
        color: white;
        border-color: #2C82FD;
    }
    /* Dividers — amber */
    hr {
        border-color: #FFA929 !important;
    }
    /* Main title — muted steel blue */
    h1 {
        color: #7BA7CC !important;
    }
</style>
"""


def main():
    st.set_page_config(
        page_title="DICOM Tag Sniffer - PHI Detection",
        page_icon=":hospital:",
        layout="wide",
    )

    st.markdown(_CUSTOM_CSS, unsafe_allow_html=True)

    init_state()

    if st.session_state.state == "startup":
        render_startup()
    elif st.session_state.state == "running":
        render_running()
    elif st.session_state.state == "dashboard":
        render_dashboard()


if __name__ == "__main__":
    main()
