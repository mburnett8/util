from data import relevant_repos
from gh_api import (
    get_repo_codescanning_alerts,
    get_repo_dependabot_alerts,
)

from util import output_file


def get_alerts_summary():
    summary_data = {}

    for repo in relevant_repos:
        db_alerts = get_repo_dependabot_alerts(repo)
        # output_file(f"data/{repo} db", db_alerts)
        crit_alerts = 0
        high_alerts = 0
        enabled = True
        if isinstance(db_alerts, list):
            for alert in db_alerts:
                if alert["state"] == "open":
                    if alert["security_advisory"]["severity"] == "critical":
                        crit_alerts += 1
                    if alert["security_advisory"]["severity"] == "high":
                        high_alerts += 1

        if isinstance(db_alerts, dict):
            if db_alerts.get("message", None) == "no analysis found":
                enabled = False

        summary_data.setdefault(repo, {})["dependabot_alerts"] = {
            "critical": crit_alerts,
            "high": high_alerts,
            "enabled": enabled,
        }

        cs_alerts = get_repo_codescanning_alerts(repo)
        # output_file(f"data/{repo} cs", cs_alerts)
        crit_alerts = 0
        high_alerts = 0
        enabled = True
        if isinstance(cs_alerts, list):
            for alert in cs_alerts:
                if alert["state"] == "open":
                    if alert["rule"]["security_severity_level"] == "critical":
                        crit_alerts += 1
                    if alert["rule"]["security_severity_level"] == "high":
                        high_alerts += 1

        if isinstance(cs_alerts, dict):
            if cs_alerts.get("message", None) == "no analysis found":
                enabled = False

        summary_data.setdefault(repo, {})["codescanning_alerts"] = {
            "critical": crit_alerts,
            "high": high_alerts,
            "enabled": enabled,
        }

    return summary_data


def get_alerts_markdown(
    summary_data,
):
    md_lines = [
        "# Security Alerts Summary",
        "",
        "Results are shown as Critical/High counts. 'NE' indicates that the feature is Not Enabled for the repository.",
        "",
        "| Repository | Dependabot Alerts | Code Scanning Alerts |",
        "|------------|-------------------|----------------------|",
    ]

    for repo, alerts in summary_data.items():
        db_count_crit = alerts.get("dependabot_alerts", 0).get("critical")
        db_count_high = alerts.get("dependabot_alerts", 0).get("high")
        db_enabled = alerts.get("dependabot_alerts", 0).get("enabled")
        cs_count_crit = alerts.get("codescanning_alerts", 0).get("critical")
        cs_count_high = alerts.get("codescanning_alerts", 0).get("high")
        cs_enabled = alerts.get("codescanning_alerts", 0).get("enabled")

        db_display = f"{db_count_crit}/{db_count_high}" if db_enabled else "NE"
        cs_display = f"{cs_count_crit}/{cs_count_high}" if cs_enabled else "NE"

        md_lines.append(f"| {repo} | {db_display} | {cs_display} |")

    md_content = "\n".join(md_lines)

    return md_content


d = get_alerts_summary()
md = get_alerts_markdown(d)

output_file("security_summary", d)
output_file("security_summary_md", md, ext="md", is_json=False)
