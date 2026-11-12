from pathlib import Path

from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_html_report(report: dict) -> str:
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("report.html.j2")
    return template.render(report=report)


def write_html_report(report: dict, path: str) -> None:
    html = render_html_report(report)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)