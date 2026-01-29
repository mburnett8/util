import os
from datetime import date

from data import relevant_repos
from fpdf import FPDF
from gh_api import (
    get_repo_codescanning_alerts,
    get_repo_dependabot_alerts,
)

from util import load_file, output_file


def get_alerts_summary(use_cache=False):
    summary_data = {}
    cs_categories = {}
    cs_categories_fe = ["/language:javascript-typescript"]
    cs_categories_be = ["/language:python", "/language:actions"]

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
                    cs_categories[cs_category] = cs_categories.get(cs_category, 0) + 1

        if isinstance(cs_alerts, dict):
            if cs_alerts.get("message", None) == "no analysis found":
                enabled = False

        summary_data.setdefault(repo, {})["codescanning_alerts"] = {
            "critical_fe": crit_alerts_fe,
            "high_fe": high_alerts_fe,
            "critical_be": crit_alerts_be,
            "high_be": high_alerts_be,
            "enabled": enabled,
        }

    return summary_data, cs_categories


def get_alerts_markdown(
    summary_data,
):
    today = date.today().strftime("%B %d, %Y")

    # Define headers
    headers = [
        "Repository",
        "Dependabot Alerts",
        "Code Scanning Alerts FE",
        "Code Scanning Alerts BE",
    ]

    # Collect all rows data first
    rows = []
    for repo, alerts in summary_data.items():
        db_count_crit = alerts.get("dependabot_alerts", 0).get("critical")
        db_count_high = alerts.get("dependabot_alerts", 0).get("high")
        db_enabled = alerts.get("dependabot_alerts", 0).get("enabled")
        cs_count_crit_fe = alerts.get("codescanning_alerts", 0).get("critical_fe")
        cs_count_high_fe = alerts.get("codescanning_alerts", 0).get("high_fe")
        cs_count_crit_be = alerts.get("codescanning_alerts", 0).get("critical_be")
        cs_count_high_be = alerts.get("codescanning_alerts", 0).get("high_be")
        cs_enabled = alerts.get("codescanning_alerts", 0).get("enabled")

        db_display = f"{db_count_crit}/{db_count_high}" if db_enabled else "NE"
        cs_display_fe = f"{cs_count_crit_fe}/{cs_count_high_fe}" if cs_enabled else "NE"
        cs_display_be = f"{cs_count_crit_be}/{cs_count_high_be}" if cs_enabled else "NE"

        rows.append([repo, db_display, cs_display_fe, cs_display_be])

    # Calculate max width for each column
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(cell))

    # Format header row
    header_row = (
        "| " + " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers)) + " |"
    )

    # Format separator row with alignment
    sep_parts = []
    for i, width in enumerate(col_widths):
        if i == 0:
            sep_parts.append(":" + "-" * (width - 1))  # Left align
        else:
            sep_parts.append(":" + "-" * (width - 2) + ":")  # Center align
    separator_row = "| " + " | ".join(sep_parts) + " |"

    # Format data rows
    data_rows = []
    for row in rows:
        formatted_cells = []
        for i, cell in enumerate(row):
            if i == 0:
                formatted_cells.append(cell.ljust(col_widths[i]))  # Left align
            else:
                formatted_cells.append(cell.center(col_widths[i]))  # Center align
        data_rows.append("| " + " | ".join(formatted_cells) + " |")

    # Build final markdown
    md_lines = [
        "# Security Alerts Summary",
        "",
        f"*Generated on {today}*",
        "",
        "Results are shown as Critical/High counts. 'NE' indicates that the feature is Not Enabled for the repository.",
        "",
        header_row,
        separator_row,
    ]
    md_lines.extend(data_rows)

    md_content = "\n".join(md_lines)
    return md_content


def markdown_to_pdf(markdown_content, output_path):
    """Convert markdown content to PDF file."""
    import tempfile

    import requests
    from fpdf import XPos, YPos

    # Color palette from coolors.co
    # 780000 (dark red), c1121f (bright red), fdf0d5 (cream), 003049 (dark blue), 669bbc (slate blue)
    colors = {
        "dark_red": (120, 0, 0),
        "bright_red": (193, 18, 31),
        "cream": (
            235,
            215,
            180,
        ),  # Lighter cream for borders
        "light_cream": (254, 250, 240),  # Lighter cream for zebra striping
        "dark_blue": (0, 48, 73),
        "slate_blue": (102, 155, 188),
        "light_slate": (210, 225, 240),  # Lighter version of slate blue
        "white": (255, 255, 255),  # White color
        "table_text": (100, 100, 100),  # Lighter gray for better readability
    }

    # Create PDF with legal size
    pdf = FPDF(format="Legal")

    # Download and add Source Sans Pro font
    font_family = "Helvetica"  # Default fallback
    try:
        # Use jsDelivr CDN with latest version
        font_url = "https://cdn.jsdelivr.net/npm/source-sans-pro@latest/TTF/SourceSansPro-Regular.ttf"
        regular_response = requests.get(font_url, timeout=10)
        regular_response.raise_for_status()

        font_url_bold = "https://cdn.jsdelivr.net/npm/source-sans-pro@latest/TTF/SourceSansPro-Bold.ttf"
        bold_response = requests.get(font_url_bold, timeout=10)
        bold_response.raise_for_status()

        font_url_italic = "https://cdn.jsdelivr.net/npm/source-sans-pro@latest/TTF/SourceSansPro-It.ttf"
        italic_response = requests.get(font_url_italic, timeout=10)
        italic_response.raise_for_status()

        # Save fonts to temporary files
        with tempfile.NamedTemporaryFile(suffix=".ttf", delete=False) as f_regular:
            f_regular.write(regular_response.content)
            font_regular_path = f_regular.name

        with tempfile.NamedTemporaryFile(suffix=".ttf", delete=False) as f_bold:
            f_bold.write(bold_response.content)
            font_bold_path = f_bold.name

        with tempfile.NamedTemporaryFile(suffix=".ttf", delete=False) as f_italic:
            f_italic.write(italic_response.content)
            font_italic_path = f_italic.name

        # Add fonts to PDF
        pdf.add_font("SourceSansPro", "", font_regular_path)
        pdf.add_font("SourceSansPro", "B", font_bold_path)
        pdf.add_font("SourceSansPro", "I", font_italic_path)

        # Use custom font
        font_family = "SourceSansPro"
        print("Successfully loaded Source Sans Pro font")
    except Exception as e:
        # Fallback if download fails
        print(
            f"Warning: Could not load Source Sans Pro font: {e}. Using Helvetica instead."
        )

    pdf.add_page()
    pdf.set_font(font_family, "", 13)

    # Parse markdown lines
    lines = markdown_content.split("\n")
    is_header_row = True
    row_count = 0

    for line in lines:
        if not line.strip():
            pdf.ln(4)  # Add spacing for empty lines
            continue

        # Handle headers
        if line.startswith("# "):
            pdf.set_font(font_family, "B", 19)
            pdf.set_text_color(*colors["dark_blue"])
            pdf.cell(0, 12, line[2:], new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(0, 0, 0)  # Reset to black
            pdf.set_font(font_family, "", 13)

        # Handle italic text (date)
        elif line.startswith("*") and line.endswith("*"):
            pdf.set_font(font_family, "I", 12)
            pdf.set_text_color(*colors["slate_blue"])
            pdf.cell(0, 7, line[1:-1], new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(0, 0, 0)  # Reset to black
            pdf.set_font(font_family, "", 13)

        # Handle table rows
        elif line.startswith("|"):
            cells = [cell.strip() for cell in line.split("|")[1:-1]]

            # Skip separator rows (rows with dashes)
            if all("-" in cell for cell in cells):
                is_header_row = False
                row_count = 0
                continue

            col_width = pdf.w / (len(cells) + 1)
            cell_height = 7  # Reduced further to fit more rows

            # Set border color and width
            pdf.set_draw_color(*colors["cream"])
            pdf.set_line_width(0.3)  # Make borders more visible

            # Header row formatting
            if is_header_row:
                pdf.set_font(font_family, "B", 11)
                pdf.set_text_color(*colors["white"])  # White text
                pdf.set_fill_color(*colors["dark_red"])  # Dark red background
                for idx, cell in enumerate(cells):
                    alignment = (
                        "L" if idx == 0 else "C"
                    )  # Left align first column, center rest
                    pdf.cell(
                        col_width,
                        cell_height,
                        cell[:20],
                        border="TB",
                        fill=True,
                        align=alignment,
                    )
                pdf.ln()
                pdf.set_text_color(0, 0, 0)  # Reset to black
                is_header_row = False
            else:
                # Alternating row colors (zebra striping)
                pdf.set_font(font_family, "", 11)
                pdf.set_text_color(*colors["table_text"])  # Lighter than black

                if row_count % 2 == 0:
                    pdf.set_fill_color(*colors["white"])  # White
                else:
                    pdf.set_fill_color(*colors["light_cream"])  # Light cream

                for idx, cell in enumerate(cells):
                    alignment = (
                        "L" if idx == 0 else "C"
                    )  # Left align first column, center rest
                    pdf.cell(
                        col_width,
                        cell_height,
                        cell[:20],
                        border="TB",
                        fill=True,
                        align=alignment,
                    )
                pdf.ln()
                pdf.set_text_color(0, 0, 0)  # Reset to black
                row_count += 1

        # Handle regular text
        else:
            pdf.set_font(font_family, "", 11)
            pdf.multi_cell(0, 5, line)
            pdf.ln(1)

    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    pdf.output(output_path)


summary, cs_categories = get_alerts_summary(use_cache=True)
md = get_alerts_markdown(summary)

timestamp = date.today().isoformat()
output_file("security_summary", summary)
output_file("security_summary", md, ext="md", is_json=False)
output_file("cs_categories", cs_categories)
markdown_to_pdf(md, "github/output/security_summary.pdf")
