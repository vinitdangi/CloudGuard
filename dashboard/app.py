import json
import logging
from datetime import datetime, timezone

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

from auth.email_delivery import send_verification_email, setting
from auth.service import (
    AuthValidationError,
    DuplicateUserError,
    EmailNotVerifiedError,
    create_email_otp,
    dashboard_login,
    signup_unverified,
    verify_email_otp,
)
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
from cloudguard.reporting.json_exporter import build_json_payload
from cloudguard.security_score import calculate_security_score, deduplicate_findings
from cloudguard.utils.sanitization import sanitize_sensitive_data
from database.db import initialize_database
from database.scan_history import get_scan_history, save_scan_history
from engine.scan_engine import ScanEngine

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
    st.session_state.pop("aws_verified_auth_method", None)
    st.session_state.pop("aws_verified_region", None)


def test_aws_connection_callback() -> None:
    """Test the submitted AWS credentials, then discard the widget values."""
    auth_method = st.session_state.get("aws_auth_method", AUTH_METHOD_ACCESS_KEY)
    region = st.session_state.get("aws_region", AWS_REGIONS[0])
    access_key_id = st.session_state.get("aws_access_key_id", "")
    secret_access_key = st.session_state.get("aws_secret_access_key", "")
    connection_session = None
    try:
        connection_session = create_aws_session(
            auth_method, region, access_key_id, secret_access_key
        )
        account_id = test_aws_connection(connection_session)
    except AWSConfigurationError as exc:
        invalidate_aws_connection()
        st.session_state["aws_operation_error"] = str(exc)
    except Exception as exc:
        invalidate_aws_connection()
        st.session_state["aws_operation_error"] = (
            f"AWS connection failed. {safe_connection_error(exc)}"
        )
    else:
        st.session_state["aws_connection_verified"] = True
        st.session_state["aws_account_id"] = account_id
        st.session_state["aws_verified_auth_method"] = auth_method
        st.session_state["aws_verified_region"] = region
    finally:
        st.session_state.pop("aws_access_key_id", None)
        st.session_state.pop("aws_secret_access_key", None)
        access_key_id = ""
        secret_access_key = ""
        connection_session = None


def run_aws_scan_callback() -> None:
    """Run a scan from submitted credentials and retain only sanitized output."""
    auth_method = st.session_state.get("aws_auth_method", AUTH_METHOD_ACCESS_KEY)
    region = st.session_state.get("aws_region", AWS_REGIONS[0])
    access_key_id = st.session_state.get("aws_access_key_id", "")
    secret_access_key = st.session_state.get("aws_secret_access_key", "")
    session = None
    try:
        start_time = datetime.now()
        session = create_aws_session(
            auth_method, region, access_key_id, secret_access_key
        )
        account_id = test_aws_connection(session)
        findings, metadata = ScanEngine(session=session).run()
        findings = deduplicate_findings(findings)
        security_score = calculate_security_score(findings)
        sensitive_values = (access_key_id, secret_access_key)

        serialized_findings = []
        for finding in findings:
            if hasattr(finding, "to_dict"):
                serialized_findings.append(finding.to_dict())
            elif isinstance(finding, dict):
                serialized_findings.append(finding)

        st.session_state["scan_findings"] = sanitize_sensitive_data(
            serialized_findings, sensitive_values=sensitive_values
        )
        st.session_state["scan_metadata"] = sanitize_sensitive_data(
            metadata or {}, sensitive_values=sensitive_values
        )
        st.session_state["scan_security_score"] = security_score
        st.session_state["scan_duration"] = (
            datetime.now() - start_time
        ).total_seconds()
        st.session_state["scan_timestamp"] = datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        )
        st.session_state["aws_connection_verified"] = True
        st.session_state["aws_account_id"] = account_id
        st.session_state["aws_verified_auth_method"] = auth_method
        st.session_state["aws_verified_region"] = region
        st.session_state["scan_completed"] = True
    except AWSConfigurationError as exc:
        invalidate_aws_connection()
        st.session_state["scan_error"] = str(exc)
    except Exception:
        invalidate_aws_connection()
        st.session_state["scan_error"] = (
            "CloudGuard scan failed. Verify AWS credentials, region, network "
            "access, and required read-only permissions."
        )
    finally:
        st.session_state.pop("aws_access_key_id", None)
        st.session_state.pop("aws_secret_access_key", None)
        access_key_id = ""
        secret_access_key = ""
        session = None


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
        options = ["Login", "Sign Up"]
        pending_email = st.session_state.get("pending_verification_email")
        if pending_email:
            options.append("Verify Email")
        if st.session_state.get("auth_mode") not in options:
            st.session_state["auth_mode"] = "Login"
        mode = st.radio(
            "Account access",
            options,
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
                    user = dashboard_login(login_value, password)
                except EmailNotVerifiedError:
                    st.error("Please verify your email before logging in.")
                except Exception:
                    st.error("Unable to sign in right now. Please try again.")
                else:
                    if user is None:
                        st.error("Invalid username/email or password.")
                    else:
                        establish_session(st.session_state, user)
                        st.rerun()
            if st.session_state.pop("signup_success", False):
                st.success("Email verified. You can now log in.")
        elif mode == "Sign Up":
            with st.form("signup_form"):
                username = st.text_input("Username")
                email = st.text_input("Email")
                password = st.text_input("Password", type="password")
                confirmation = st.text_input("Confirm password", type="password")
                submitted = st.form_submit_button("CREATE ACCOUNT", type="primary", use_container_width=True)
            if submitted:
                try:
                    user = signup_unverified(username, email, password, confirmation)
                except AuthValidationError as exc:
                    st.error(str(exc))
                except DuplicateUserError:
                    st.error("That username or email is already registered. Try logging in.")
                except Exception:
                    st.error("Unable to create your account right now. Please try again.")
                else:
                    st.session_state["pending_verification_email"] = user.email
                    st.session_state["auth_mode"] = "Verify Email"
                    try:
                        otp = create_email_otp(
                            user.email, secret=setting("CLOUDGUARD_OTP_SECRET")
                        )
                        send_verification_email(user.email, otp)
                    except Exception:
                        st.session_state["otp_delivery_pending"] = True
                    else:
                        st.session_state["otp_delivery_pending"] = False
                    st.rerun()
        else:
            st.info(f"Enter the 6-digit code sent to {pending_email}.")
            if st.session_state.pop("otp_delivery_pending", False):
                st.warning(
                    "We couldn't send the verification email. Check the email settings "
                    "and use Resend OTP."
                )
            with st.form("verify_email_form"):
                otp = st.text_input("6-digit verification code", max_chars=6)
                submitted = st.form_submit_button(
                    "VERIFY EMAIL", type="primary", use_container_width=True
                )
            if submitted:
                if len(otp) != 6 or not otp.isdigit():
                    st.error("Enter the 6-digit code from your email.")
                else:
                    try:
                        result = verify_email_otp(
                            pending_email,
                            otp,
                            secret=setting("CLOUDGUARD_OTP_SECRET"),
                        )
                    except Exception:
                        st.error("Unable to verify your email right now. Please try again.")
                    else:
                        messages = {
                            "invalid": "That verification code is incorrect. Try again.",
                            "expired": "That verification code expired. Request a new one.",
                            "too_many_attempts": "Too many incorrect attempts. Request a new code.",
                            "missing": "No active verification code. Request a new one.",
                        }
                        if result == "verified":
                            st.session_state.pop("pending_verification_email", None)
                            st.session_state["auth_mode"] = "Login"
                            st.session_state["signup_success"] = True
                            st.rerun()
                        st.error(messages.get(result, "Unable to verify this code."))
            if st.button("Resend OTP", use_container_width=True):
                try:
                    otp = create_email_otp(
                        pending_email, secret=setting("CLOUDGUARD_OTP_SECRET")
                    )
                    send_verification_email(pending_email, otp)
                except Exception:
                    st.error("Unable to send a new verification code. Check email settings.")
                else:
                    st.success("A new verification code has been sent.")


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
    "Access keys are requested separately for each connection test or scan and "
    "cleared when that form is submitted. They are never retained in the session."
)

with st.form("aws_operation_form", clear_on_submit=True):
    auth_method = st.radio(
        "Authentication Method",
        [AUTH_METHOD_ACCESS_KEY, AUTH_METHOD_ENVIRONMENT],
        horizontal=True,
        key="aws_auth_method",
    )
    region = st.selectbox(
        "AWS Region",
        AWS_REGIONS,
        index=AWS_REGIONS.index("ap-southeast-2"),
        key="aws_region",
    )

    access_key_id = ""
    secret_access_key = ""
    if auth_method == AUTH_METHOD_ACCESS_KEY:
        st.text_input("AWS Access Key ID", key="aws_access_key_id")
        secret_access_key = st.text_input(
            "AWS Secret Access Key", type="password", key="aws_secret_access_key"
        )
    else:
        st.caption("Uses the existing boto3 credential chain (AWS CLI, environment, or IAM role).")

    st.form_submit_button(
        "Test AWS Connection",
        type="secondary",
        on_click=test_aws_connection_callback,
    )
    st.form_submit_button(
        "Run Cloud Security Scan",
        type="primary",
        on_click=run_aws_scan_callback,
    )

if error_message := st.session_state.pop("aws_operation_error", None):
    st.error(error_message)

if error_message := st.session_state.pop("scan_error", None):
    st.error(error_message)

if auth_method != st.session_state.get("aws_verified_auth_method") or region != st.session_state.get("aws_verified_region"):
    invalidate_aws_connection()

if st.session_state.get("aws_connection_verified"):
    st.success("AWS connection successful")
    st.caption(f"AWS Account: {st.session_state['aws_account_id']}  ·  Region: {region}")
else:
    st.warning("Test the AWS connection successfully before starting a scan.")

# Scan Execution

if st.session_state.pop("scan_completed", False):
    findings = st.session_state["scan_findings"]
    metadata = st.session_state["scan_metadata"]
    security_score = st.session_state["scan_security_score"]
    duration = st.session_state["scan_duration"]
    scan_timestamp = st.session_state["scan_timestamp"]


    st.success("Scan Completed!")

    findings = deduplicate_findings(findings)
    security_score = calculate_security_score(findings)

    # Convert Findings

    all_findings = []

    for finding in findings:

        if hasattr(finding, "to_dict"):
            all_findings.append(finding.to_dict())

        elif isinstance(finding, dict):
            all_findings.append(finding)

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "PASS"]
    severity_counts = pd.Series({
        "CRITICAL": security_score.critical_count,
        "HIGH": security_score.high_count,
        "MEDIUM": security_score.medium_count,
        "LOW": security_score.low_count,
        "PASS": security_score.passed_count,
    }).reindex(severity_order, fill_value=0)
    try:
        save_scan_history(
            username=st.session_state["username"],
            scan_timestamp=scan_timestamp,
            aws_account_id=st.session_state["aws_account_id"],
            aws_region=st.session_state["aws_region"],
            security_score=security_score.score,
            total_findings=security_score.total_findings,
            critical_count=security_score.critical_count,
            high_count=security_score.high_count,
            medium_count=security_score.medium_count,
            low_count=security_score.low_count,
            passed_count=security_score.passed_count,
        )
    except Exception as exc:
        logger.error("Scan history save failed (%s)", type(exc).__name__)
        st.warning("The scan completed, but its history entry could not be saved.")

    # Security Score and severity breakdown

    st.subheader("Security Score")
    score_columns = st.columns([1, 2])
    score_columns[0].metric("SECURITY SCORE", f"{security_score.score:g} / 100")
    score_columns[0].markdown(f"**{security_score.rating}**")
    breakdown_columns = score_columns[1].columns(5)
    for column, severity, count in zip(
        breakdown_columns,
        ("Critical", "High", "Medium", "Low", "Passed"),
        (
            security_score.critical_count,
            security_score.high_count,
            security_score.medium_count,
            security_score.low_count,
            security_score.passed_count,
        ),
    ):
        column.metric(severity, count)

    if security_score.total_findings == 0:
        st.info("No checks were returned. The score has zero assessment coverage.")
    else:
        most_severe = next(
            (severity for severity in ("critical", "high", "medium", "low")
             if security_score.severity_summary[severity]),
            None,
        )
        if most_severe:
            finding_count = security_score.severity_summary[most_severe]
            penalty = security_score.penalty_breakdown[most_severe.upper()]
            st.caption(
                f"{finding_count} {most_severe.title()} finding(s) contribute "
                f"{penalty} weighted penalty points to the score."
            )
        with st.expander("Understand the score"):
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                st.write(
                    f"{severity.title()}: {security_score.severity_summary[severity.lower()]} "
                    f"× {security_score.severity_weights[severity]} "
                    f"= {security_score.penalty_breakdown[severity]} penalty points"
                )
            st.write(
                f"Weighted penalty: {security_score.total_penalty} / "
                f"{security_score.maximum_penalty}. Final score: "
                f"{security_score.score:g} / 100."
            )

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

    col2.metric("Total Findings", security_score.total_findings)

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
        # JSON Export
        st.subheader("Export Assessment Data")

        json_report = json.dumps(
            build_json_payload(
                findings,
                ["All"],
                security_score,
            ),
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
            security_score=security_score,
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
