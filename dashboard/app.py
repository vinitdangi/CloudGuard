from datetime import datetime

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

from cloudguard.aws.session import create_session
from engine.scan_engine import ScanEngine


st.set_page_config(
    page_title="CloudGuard Security",
    page_icon="🛡️",
    layout="wide",
)

st.title("CloudGuard Security Assessment Dashboard")
st.markdown(
    "Scan and monitor your AWS cloud security configurations in real time."
)


# Sidebar

st.sidebar.header("Scan Setup")

st.sidebar.subheader("Scan Scope")
st.sidebar.info(
    "CloudGuard scans S3, IAM, and VPC using the active plugin registry."
)

# Scan Execution

if st.sidebar.button(" Run Cloud Security Scan", type="primary"):

    with st.spinner("Scanning AWS Environment. Please wait..."):

        start_time = datetime.now()

        try:
            session = create_session()

            # Use the same ScanEngine as the CLI
            engine = ScanEngine(session=session)

            findings, metadata = engine.run()

        except Exception as e:
            st.error(f"CloudGuard scan failed: {e}")
            st.stop()

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()


    st.success("Scan Completed!")

    # Convert Findings

    all_findings = []

    for finding in findings:

        if hasattr(finding, "to_dict"):
            all_findings.append(finding.to_dict())

        elif isinstance(finding, dict):
            all_findings.append(finding)

    # Metrics

    resources_with_findings = len(
        {
            finding.get("resource")
            for finding in all_findings
            if finding.get("resource")
        }
    )

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Resources with Findings",
        resources_with_findings,
    )

    col2.metric(
        "Total Findings",
        len(all_findings),
    )

    col3.metric(
        "Scan Execution Time",
        f"{duration:.2f} seconds",
    )

    # Findings

    if all_findings:

        df = pd.DataFrame(all_findings)

        # Normalize Severity

        severity_order = [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "PASS",
        ]

        severity_values = []

        for finding in all_findings:

            passed = finding.get("passed", False)

            if passed:
                severity_values.append("PASS")
                continue

            severity = str(
                finding.get("severity", "HIGH")
            ).upper()

            if severity not in severity_order:
                severity = "HIGH"

            severity_values.append(severity)


        severity_counts = (
            pd.Series(severity_values)
            .value_counts()
            .reindex(severity_order, fill_value=0)
        )

        # Severity Distribution

        st.subheader("Security Severity Distribution")

        chart_col, data_col = st.columns([1, 2])


        with chart_col:

            fig, ax = plt.subplots(figsize=(5, 5))

            # Remove zero-count severities from the pie
            visible_counts = severity_counts[
                severity_counts > 0
            ]

            ax.pie(
                visible_counts,
                labels=list(visible_counts.index),
                autopct="%1.1f%%",
                startangle=90,
            )

            ax.axis("equal")

            st.pyplot(fig)

            plt.close(fig)
        # Findings Table

        with data_col:

            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
            )
        # Severity Summary

        st.subheader("🔎 Severity Summary")

        summary_cols = st.columns(len(severity_order))

        for column, severity in zip(
            summary_cols,
            severity_order,
        ):

            column.metric(
                severity,
                int(severity_counts[severity]),
            )

        # JSON Export
        st.subheader("Export Assessment Data")

        json_report = df.to_json(
            orient="records",
            indent=4,
        )

        st.download_button(
            label="⬇ Download CloudGuard JSON Report",
            data=json_report,
            file_name=(
                f"cloudguard_report_"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            ),
            mime="application/json",
        )


    else:

        st.info(
            "No security vulnerabilities or findings were detected."
        )