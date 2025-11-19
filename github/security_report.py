from data import relevant_repos
from gh_api import (
    get_repo_codescanning_alerts,
    get_repo_dependabot_alerts,
)

from util import load_file, output_file


def get_alerts_summary(use_cache=False):
    summary_data = {}
    cs_categories = {}
    cs_categories_fe = ["/language:javascript-typescript"]
    cs_categories_be = ["/language:python"]
    cs_categories_other = ["/language:actions"]

    if use_cache:
        summary_data = load_file("security_summary")
        cs_categories = load_file("cs_categories")
        return summary_data, cs_categories

    for repo in relevant_repos:
        db_alerts = get_repo_dependabot_alerts(repo)
        output_file(f"data/{repo} db", db_alerts)
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
        output_file(f"data/{repo} cs", cs_alerts)
        crit_alerts_fe = 0
        high_alerts_fe = 0
        crit_alerts_be = 0
        high_alerts_be = 0
        crit_alerts_other = 0
        high_alerts_other = 0
        enabled = True
        if isinstance(cs_alerts, list):
            for alert in cs_alerts:
                if alert["state"] == "open":
                    cs_category = alert["most_recent_instance"]["category"]
                    cs_severity = alert["rule"]["security_severity_level"]
                    if cs_category in cs_categories_fe:
                        if cs_severity == "critical":
                            crit_alerts_fe += 1
                        if cs_severity == "high":
                            high_alerts_fe += 1
                    if cs_category in cs_categories_be:
                        if cs_severity == "critical":
                            crit_alerts_be += 1
                        if cs_severity == "high":
                            high_alerts_be += 1
                    if cs_category in cs_categories_other:
                        if cs_severity == "critical":
                            crit_alerts_other += 1
                        if cs_severity == "high":
                            high_alerts_other += 1
                    cs_categories[cs_category] = cs_categories.get(cs_category, 0) + 1

        if isinstance(cs_alerts, dict):
            if cs_alerts.get("message", None) == "no analysis found":
                enabled = False

        summary_data.setdefault(repo, {})["codescanning_alerts"] = {
            "critical_fe": crit_alerts_fe,
            "high_fe": high_alerts_fe,
            "critical_be": crit_alerts_be,
            "high_be": high_alerts_be,
            "critical_other": crit_alerts_other,
            "high_other": high_alerts_other,
            "enabled": enabled,
        }

    return summary_data, cs_categories


def get_alerts_markdown(
    summary_data,
):
    md_lines = [
        "# Security Alerts Summary",
        "",
        "Results are shown as Critical/High counts. 'NE' indicates that the feature is Not Enabled for the repository.",
        "",
        "| Repository | Dependabot Alerts | Code Scanning Alerts FE | Code Scanning Alerts BE | Code Scanning Alerts Other |",
        "|------------|-------------------|-------------------------|-------------------------|----------------------------|",
    ]

    for repo, alerts in summary_data.items():
        db_count_crit = alerts.get("dependabot_alerts", 0).get("critical")
        db_count_high = alerts.get("dependabot_alerts", 0).get("high")
        db_enabled = alerts.get("dependabot_alerts", 0).get("enabled")
        cs_count_crit_fe = alerts.get("codescanning_alerts", 0).get("critical_fe")
        cs_count_high_fe = alerts.get("codescanning_alerts", 0).get("high_fe")
        cs_count_crit_be = alerts.get("codescanning_alerts", 0).get("critical_be")
        cs_count_high_be = alerts.get("codescanning_alerts", 0).get("high_be")
        cs_count_crit_other = alerts.get("codescanning_alerts", 0).get("critical_other")
        cs_count_high_other = alerts.get("codescanning_alerts", 0).get("high_other")
        cs_enabled = alerts.get("codescanning_alerts", 0).get("enabled")

        db_display = f"{db_count_crit}/{db_count_high}" if db_enabled else "NE"
        cs_display_fe = f"{cs_count_crit_fe}/{cs_count_high_fe}" if cs_enabled else "NE"
        cs_display_be = f"{cs_count_crit_be}/{cs_count_high_be}" if cs_enabled else "NE"
        cs_display_other = (
            f"{cs_count_crit_other}/{cs_count_high_other}" if cs_enabled else "NE"
        )

        md_lines.append(
            f"| {repo} | {db_display} | {cs_display_fe} | {cs_display_be} | {cs_display_other} |"
        )

    md_content = "\n".join(md_lines)

    return md_content


summary, cs_categories = get_alerts_summary(use_cache=True)
md = get_alerts_markdown(summary)

output_file("security_summary", summary)
output_file("security_summary", md, ext="md", is_json=False)
output_file("cs_categories", cs_categories)
