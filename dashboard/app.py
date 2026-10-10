import logging
from datetime import datetime, timezone

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

from auth.service import AuthValidationError, DuplicateUserError, login, signup
from auth.session import clear_session, establish_session
from cloudguard.aws.configuration import (
    AUTH_METHOD_ACCESS_KEY,
    AUTH_METHOD_ENVIRONMENT,
    AWS_REGIONS,
    AWSConfigurationError,
    clear_aws_session_state,
    create_aws_session,
    safe_connection_error,
    test_aws_connection,
)
from cloudguard.reporting.pdf_exporter import generate_pdf_report
from database.db import initialize_database
from database.scan_history import get_scan_history, save_scan_history
from engine.scan_engine import ScanEngine
from cloudguard.posture import SecurityPosture

logger = logging.getLogger(__name__)


st.set_page_config(
    page_title="CloudGuard Security",
    page_icon="🛡️",
    layout="wide",
)

initialize_database()


def invalidate_aws_connection() -> None:
    """Require a fresh STS check after AWS configuration changes."""
    st.session_state["aws_connection_verified"] = False
    st.session_state.pop("aws_account_id", None)


def change_aws_auth_method() -> None:
    """Clear manual credentials when switching authentication methods."""
    invalidate_aws_connection()
    st.session_state.pop("aws_access_key_id", None)
    st.session_state.pop("aws_secret_access_key", None)


def logout() -> None:
    """Clear CloudGuard identity and all temporary AWS configuration."""
    clear_session(st.session_state)
    clear_aws_session_state(st.session_state)


def render_authentication() -> None:
    """Display account login or signup for logged-out visitors."""
    if st.session_state.pop("switch_to_login", False):
        st.session_state["auth_mode"] = "Login"

    st.markdown(
        """
        <style>
        .cg-hero { text-align: center; padding: 2.2rem 0 1rem; }
        .cg-hero h1 { color: #13b8a6; letter-spacing: .08em; margin-bottom: .2rem; }
        .cg-hero p { color: #8292a6; font-size: 1.05rem; }
        [data-testid="stForm"] { border: 1px solid rgba(120, 150, 180, .25);
          border-radius: 12px; padding: 1.5rem; }
        </style>
        <div class="cg-hero"><h1>🛡️ CLOUDGUARD</h1>
        <p>AWS Cloud Security Platform</p></div>
        """,
        unsafe_allow_html=True,
    )
    _, panel, _ = st.columns([1, 1.15, 1])
    with panel:
        mode = st.radio(
            "Account access",
            ["Login", "Sign Up"],
            horizontal=True,
            label_visibility="collapsed",
            key="auth_mode",
        )
        if mode == "Login":
            with st.form("login_form"):
                login_value = st.text_input("Email or username")
                password = st.text_input("Password", type="password")
                submitted = st.form_submit_button("LOGIN", type="primary", use_container_width=True)
            if submitted:
                try:
                    user = login(login_value, password)
                except Exception:
                    st.error("Unable to sign in right now. Please try again.")
                else:
                    if user is None:
                        st.error("Invalid username/email or password.")
                    else:
                        establish_session(st.session_state, user)
                        st.rerun()
            if st.session_state.pop("signup_success", False):
                st.success("Account created successfully. Please log in.")
        else:
            with st.form("signup_form"):
                username = st.text_input("Username")
                email = st.text_input("Email")
                password = st.text_input("Password", type="password")
                confirmation = st.text_input("Confirm password", type="password")
                submitted = st.form_submit_button("CREATE ACCOUNT", type="primary", use_container_width=True)
            if submitted:
                try:
                    signup(username, email, password, confirmation)
                except AuthValidationError as exc:
                    st.error(str(exc))
                except DuplicateUserError:
                    st.error("That username or email is already registered. Try logging in.")
                except Exception:
                    st.error("Unable to create your account right now. Please try again.")
                else:
                    st.session_state["signup_success"] = True
                    st.session_state["switch_to_login"] = True
                    st.rerun()


if not (st.session_state.get("authenticated") and st.session_state.get("user_id")):
    render_authentication()
    st.stop()

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
st.sidebar.caption(f"Signed in as {st.session_state['username']}")
st.sidebar.button("Logout", on_click=logout)

st.header("AWS Cloud Configuration")
st.caption("Configure a temporary AWS connection for a read-only security assessment.")
st.info(
    "Credentials stay in this authenticated Streamlit session and are not saved "
    "to CloudGuard's database or reports. CloudGuard uses them only for AWS checks."
)

auth_method = st.radio(
    "Authentication Method",
    [AUTH_METHOD_ACCESS_KEY, AUTH_METHOD_ENVIRONMENT],
    horizontal=True,
    key="aws_auth_method",
    on_change=change_aws_auth_method,
)
region = st.selectbox(
    "AWS Region",
    AWS_REGIONS,
    index=AWS_REGIONS.index("ap-southeast-2"),
    key="aws_region",
    on_change=invalidate_aws_connection,
)

access_key_id = ""
secret_access_key = ""
if auth_method == AUTH_METHOD_ACCESS_KEY:
    access_key_id = st.text_input(
        "AWS Access Key ID",
        key="aws_access_key_id",
        on_change=invalidate_aws_connection,
    )
    secret_access_key = st.text_input(
        "AWS Secret Access Key",
        type="password",
        key="aws_secret_access_key",
        on_change=invalidate_aws_connection,
    )
else:
    st.caption("Uses the existing boto3 credential chain (AWS CLI, environment, or IAM role).")

if st.button("Test AWS Connection", type="secondary"):
    try:
        connection_session = create_aws_session(
            auth_method,
            region,
            access_key_id,
            secret_access_key,
        )
        account_id = test_aws_connection(connection_session)
    except AWSConfigurationError as exc:
        invalidate_aws_connection()
        st.error(str(exc))
    except Exception as exc:
        invalidate_aws_connection()
        st.error(f"AWS connection failed. {safe_connection_error(exc)}")
    else:
        st.session_state["aws_connection_verified"] = True
        st.session_state["aws_account_id"] = account_id

if st.session_state.get("aws_connection_verified"):
    st.success("AWS connection successful")
    st.caption(f"AWS Account: {st.session_state['aws_account_id']}  ·  Region: {region}")
else:
    st.warning("Test the AWS connection successfully before starting a scan.")

# Scan Execution

if st.sidebar.button(
    " Run Cloud Security Scan",
    type="primary",
    disabled=not st.session_state.get("aws_connection_verified", False),
):

    with st.spinner("Scanning AWS Environment. Please wait..."):

        start_time = datetime.now()

        try:
            session = create_aws_session(
                st.session_state["aws_auth_method"],
                st.session_state["aws_region"],
                st.session_state.get("aws_access_key_id", ""),
                st.session_state.get("aws_secret_access_key", ""),
            )

            # Use the same ScanEngine as the CLI
            engine = ScanEngine(session=session)

            findings, metadata = engine.run()

        except Exception:
            st.error(
                "CloudGuard scan failed. Verify AWS credentials, region, network "
                "access, and required read-only permissions."
            )
            st.stop()

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        scan_timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")


    st.success("Scan Completed!")

    # Convert Findings

    all_findings = []

    for finding in findings:

        if hasattr(finding, "to_dict"):
            all_findings.append(finding.to_dict())

        elif isinstance(finding, dict):
            all_findings.append(finding)

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "PASS"]
    severity_values = []
    for finding in all_findings:
        if finding.get("passed"):
            severity_values.append("PASS")
            continue
        severity = str(finding.get("severity", "HIGH")).upper()
        severity_values.append(severity if severity in severity_order else "HIGH")
    severity_counts = pd.Series(severity_values).value_counts().reindex(
        severity_order, fill_value=0
    )
    posture = SecurityPosture.calculate(findings)
    try:
        save_scan_history(
            username=st.session_state["username"],
            scan_timestamp=scan_timestamp,
            aws_account_id=st.session_state["aws_account_id"],
            aws_region=st.session_state["aws_region"],
            security_score=posture["score"],
            total_findings=len(all_findings),
            critical_count=int(severity_counts["CRITICAL"]),
            high_count=int(severity_counts["HIGH"]),
            medium_count=int(severity_counts["MEDIUM"]),
            low_count=int(severity_counts["LOW"]),
            passed_count=int(severity_counts["PASS"]),
        )
    except Exception as exc:
        logger.error("Scan history save failed (%s)", type(exc).__name__)
        st.warning("The scan completed, but its history entry could not be saved.")

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

    try:
        pdf_report = generate_pdf_report(
            findings,
            {
                **(metadata or {}),
                "aws_account_id": st.session_state.get("aws_account_id"),
                "region": st.session_state.get("aws_region"),
                "scan_timestamp": scan_timestamp,
                "scan_duration_seconds": duration,
                "scan_status": "Completed",
                "cloudguard_version": "v1.0.0",
            },
            sensitive_values=(
                st.session_state.get("aws_access_key_id", ""),
                st.session_state.get("aws_secret_access_key", ""),
            ),
        )
    except Exception as exc:
        logger.error("PDF report generation failed (%s)", type(exc).__name__)
        st.error("PDF report generation failed. Please try again after the scan.")
    else:
        st.download_button(
            label="Download PDF Report",
            data=pdf_report,
            file_name=f"cloudguard_security_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mime="application/pdf",
            on_click="ignore",
        )

st.subheader("Scan History")
try:
    history = get_scan_history(st.session_state["username"])
except Exception as exc:
    logger.error("Scan history load failed (%s)", type(exc).__name__)
    st.error("Scan history is temporarily unavailable.")
else:
    if history:
        history_frame = pd.DataFrame(history)
        history_frame = history_frame.rename(columns={
            "scan_timestamp": "Timestamp",
            "aws_account_id": "AWS Account",
            "aws_region": "Region",
            "security_score": "Security Score",
            "total_findings": "Total Findings",
            "critical_count": "Critical",
            "high_count": "High",
            "medium_count": "Medium",
            "low_count": "Low",
            "passed_count": "Passed",
        })
        st.dataframe(
            history_frame[[
                "Timestamp", "AWS Account", "Region", "Security Score",
                "Total Findings", "Critical", "High", "Medium", "Low", "Passed",
            ]],
            width="stretch",
            hide_index=True,
        )
    else:
        st.info("No scan history yet. Complete a successful scan to see it here.")
