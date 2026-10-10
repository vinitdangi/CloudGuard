import os

from datetime import datetime

from cloudguard.findings import COLORS
from cloudguard.utils.logger import feeder


def export_to_html(all_findings, running_tasks):

    findings_list = [finding.to_dict() for finding in all_findings]

    table_rows = ""

    for f in findings_list:

        passed = f.get("passed", False)

        severity = (
            str(f.get("severity", "HIGH")).upper()
            if not passed
            else "PASS"
        )

        resource = f.get("resource", "Global / Account")
        check = f.get("check", "Security Check")
        issue = f.get("issue", "Secure and compliant")
        recommendation = f.get(
            "recommendation",
            "No action required"
        )
        compliance = f.get("compliance", [])
        cis_html = ""
        if compliance:
            compliance_blocks=[]
            
            for control in compliance:
                framework=control.get("framework",'')
                version=control.get("version",'')
                control_id=control.get('control_id','')
                title=control.get('title','')
                mapping=control.get('mapping','')
                note=control.get('note','')
                
            
                block = f"""
                <div style="
                    margin-top: 10px;
                    padding: 8px 10px;
                    background: #f8fafc;
                    border-left: 3px solid #6366f1;
                    border-radius: 4px;
                    font-size: 0.85em;
                ">
                    <strong style="color: #4338ca;">
                        CIS {control_id}
                    </strong>
                    {"<br><span style='color: #475569;'>" + title + "</span>" if title else ""}
                    {
                        "<br><span style='color: #64748b;'>" +
                        framework +
                        (" " + version if version else "") +
                        "</span>"
                        if framework
                        else ""
                    }
                    {
                        "<br><span style='color: #64748b;'>Mapping: " +
                        mapping +
                        "</span>"
                        if mapping
                        else ""
                    }
                    {
                        "<br><span style='color: #64748b;'>" +
                        note +
                        "</span>"
                        if note
                        else ""
                    }
                </div>
            """
                compliance_blocks.append(block)
            cis_html="".join(compliance_blocks)
        

        # Preserve recommendation line breaks in HTML
        recommendation = str(recommendation).replace("\n", "<br>")

        # Colour badge for severity
        if passed:

            bg_color, text_color = "#e8f5e9", "#2e7d32"
            badge_text = "PASS"

        elif severity == "CRITICAL":

            bg_color, text_color = "#f3e5f5", "#7b1fa2"
            badge_text = "CRITICAL"

        elif severity == "HIGH":

            bg_color, text_color = "#ffebee", "#c62828"
            badge_text = "HIGH"

        elif severity == "MEDIUM":

            bg_color, text_color = "#fffde7", "#f57f17"
            badge_text = "MEDIUM"

        else:

            bg_color, text_color = "#e3f2fd", "#1565c0"
            badge_text = "LOW"

        table_rows += f"""
        <tr>

            <td>
                <span style="
                    background: {bg_color};
                    color: {text_color};
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-weight: bold;
                    font-size: 0.85em;
                ">
                    {badge_text}
                </span>
            </td>

            <td>
                <strong>{resource}</strong>
            </td>

            <td>
                <strong>{check}</strong>
                <br>
                <span style="
                    color: #64748b;
                    font-size: 0.9em;
                ">
                {issue}
                </span>
                {cis_html}
            </td>

            <td style="
                color: #0d9488;
                font-size: 0.9em;
                line-height: 1.6;
            ">
                {recommendation}
            </td>

        </tr>
        """

    tasks_str = (
        ", ".join(running_tasks)
        if running_tasks
        else "All Plugins"
    )

    html_content = f"""
<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>CloudGuard Security Report</title>

    <style>

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 40px;
            background: #f5f7fb;
            color: #333;
        }}

        .container {{
            max-width: 1100px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}

        h1 {{
            color: #1e3a8a;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 10px;
            margin-top: 0;
        }}

        .metadata {{
            background: #f8fafc;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 0.9em;
        }}

        .metadata p {{
            margin: 6px 0;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}

        th,
        td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
            vertical-align: top;
        }}

        th {{
            background: #f1f5f9;
            color: #475569;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        tr:hover {{
            background: #f8fafc;
        }}

        td strong {{
            color: #1e293b;
        }}

    </style>

</head>

<body>

    <div class="container">

        <h1>CloudGuard Security Assessment Report</h1>

        <div class="metadata">

            <p>
                <strong>Generated:</strong>
                {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </p>

            <p>
                <strong>Tasks Executed:</strong>
                {tasks_str}
            </p>

            <p>
                <strong>Total Findings:</strong>
                {len(all_findings)}
            </p>

        </div>

        <table>

            <thead>

                <tr>
                    <th>Status</th>
                    <th>Resource</th>
                    <th>Check &amp; Issue</th>
                    <th>Recommendation</th>
                </tr>

            </thead>

            <tbody>

                {
                    table_rows
                    if table_rows
                    else "<tr><td colspan='4'>No findings recorded.</td></tr>"
                }

            </tbody>

        </table>

    </div>

</body>

</html>
"""

    report_filename = "cloudguard_report.html"

    with open(
        report_filename,
        "w",
        encoding="utf-8"
    ) as html_file:

        html_file.write(html_content)

    feeder(
        f"*\n*"
        f"{COLORS['GREEN']}"
        f"HTML report exported successfully to "
        f"{report_filename}!"
        f"{COLORS['RESET']}"
    )