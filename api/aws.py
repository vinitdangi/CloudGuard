"""AWS connection and security scan API routes for CloudGuard."""

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response

from api.schemas import (
    AWSConnectionRequest,
    AWSConnectionResponse,
)
from cloudguard.aws.configuration import (
    AWSConfigurationError,
    create_aws_session,
    safe_connection_error,
    test_aws_connection,
)
from cloudguard.reporting.pdf_exporter import generate_pdf_report
from cloudguard.security_score import (
    calculate_security_score,
    deduplicate_findings,
)
from database.auth_repository import AuthRepository
from database.scan_history import (
    get_latest_scan_result,
    get_scan_history,
    sanitize_scan_data,
    save_scan_history,
)
from engine.scan_engine import ScanEngine


router = APIRouter(prefix="/api/aws", tags=["AWS"])


def _authenticated_username(request: Request) -> str:
    user_id = request.session.get("user_id")
    try:
        user = AuthRepository.find_by_id(int(user_id)) if user_id is not None else None
    except (TypeError, ValueError):
        user = None
    if user is None or not user.email_verified:
        request.session.clear()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    return user.username


def _latest_scan_for_user(request: Request) -> dict:
    scan = get_latest_scan_result(_authenticated_username(request))
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No complete scan result is available yet.",
        )
    return scan


@router.get("/history")
def get_user_scan_history(request: Request) -> dict:
    """Return scan history for the authenticated user."""
    username = _authenticated_username(request)
    return {"scans": get_scan_history(username)}


@router.get("/latest-scan")
def get_user_latest_scan(request: Request) -> dict:
    """Return the authenticated user's latest complete scan result, if any."""
    username = _authenticated_username(request)
    return {"scan": get_latest_scan_result(username)}


@router.get("/latest-scan/json")
def download_latest_json_report(request: Request) -> JSONResponse:
    """Download the authenticated user's persisted latest complete scan."""
    scan = _latest_scan_for_user(request)
    return JSONResponse(
        content=sanitize_scan_data(scan),
        headers={"Content-Disposition": 'attachment; filename="cloudguard_latest_scan.json"'},
    )


@router.get("/latest-scan/pdf")
def download_latest_pdf_report(request: Request) -> Response:
    """Build a PDF report from the authenticated user's persisted latest scan."""
    scan = _latest_scan_for_user(request)
    report = generate_pdf_report(
        scan["findings"],
        {
            **scan["metadata"],
            "aws_account_id": scan["aws_account_id"],
            "aws_region": scan["aws_region"],
            "scan_timestamp": scan["scan_timestamp"],
            "duration_seconds": scan["duration_seconds"],
            "cloudguard_version": "v1.0.0",
        },
        security_score=scan["security_score"],
    )
    return Response(
        content=report,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="cloudguard_security_assessment.pdf"'},
    )


@router.post("/test", response_model=AWSConnectionResponse)
def test_connection(payload: AWSConnectionRequest, request: Request) -> AWSConnectionResponse:
    """Test AWS credentials and return only safe connection metadata."""
    _authenticated_username(request)
    try:
        session = create_aws_session(
            payload.auth_method,
            payload.region,
            payload.access_key_id,
            payload.secret_access_key,
        )

        account_id = test_aws_connection(session)

    except AWSConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=safe_connection_error(exc),
        ) from exc

    return AWSConnectionResponse(
        connected=True,
        account_id=account_id,
        region=payload.region,
        message="AWS connection successful.",
    )


@router.post("/scan")
def run_security_scan(payload: AWSConnectionRequest, request: Request) -> dict:
    """Run the CloudGuard security scan against the configured AWS account."""
    username = _authenticated_username(request)

    try:
        session = create_aws_session(
            payload.auth_method,
            payload.region,
            payload.access_key_id,
            payload.secret_access_key,
        )

        account_id = test_aws_connection(session)

        start_time = datetime.now(timezone.utc)

        engine = ScanEngine(session=session)
        findings, metadata = engine.run()

        end_time = datetime.now(timezone.utc)

        duration_seconds = round(
            (end_time - start_time).total_seconds(),
            2,
        )

    except AWSConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=safe_connection_error(exc),
        ) from exc

    findings = deduplicate_findings(findings)

    security_score = calculate_security_score(findings)

    finding_data = [
        finding.to_dict() if hasattr(finding, "to_dict") else finding
        for finding in findings
    ]

    scan_timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    scan_result = sanitize_scan_data({
        "scan_timestamp": scan_timestamp,
        "aws_account_id": account_id,
        "aws_region": payload.region,
        "duration_seconds": duration_seconds,
        "metadata": metadata,
        "security_score": security_score.to_dict(),
        "findings": finding_data,
    }, (payload.access_key_id, payload.secret_access_key))

    save_scan_history(
        username=username,
        scan_timestamp=scan_timestamp,
        aws_account_id=account_id,
        aws_region=payload.region,
        security_score=security_score.score,
        total_findings=security_score.total_findings,
        critical_count=security_score.critical_count,
        high_count=security_score.high_count,
        medium_count=security_score.medium_count,
        low_count=security_score.low_count,
        passed_count=security_score.passed_count,
        scan_result=scan_result,
        sensitive_values=(payload.access_key_id, payload.secret_access_key),
    )

    return scan_result
