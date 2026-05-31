from rich.console import Console
from rich.table import Table
from rich.text import Text
from gtfoguard.models import RiskScore


_SEVERITY_STYLES = {
    "HIGH": "bold white on red",
    "MEDIUM": "bold black on yellow",
    "LOW": "cyan",
}


def _severity_cell(severity: str) -> Text:
    return Text(f" {severity} ", style=_SEVERITY_STYLES.get(severity, "white"))


class Display:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def render(self, results: list[RiskScore]) -> None:
        if not results:
            self.console.print("[green]No suspicious activity detected.[/green]")
            return

        table = Table(
            title=f"GTFOGuard — {len(results)} detection(s)",
            title_style="bold",
            header_style="bold",
            show_lines=False,
        )
        table.add_column("PID", justify="right", no_wrap=True)
        table.add_column("User", no_wrap=True)
        table.add_column("Binary", no_wrap=True)
        table.add_column("Detection Type", no_wrap=True)
        table.add_column("Severity", justify="center", no_wrap=True)
        table.add_column("Score", justify="right", no_wrap=True)
        table.add_column("Explanation")

        for result in sorted(results, key=lambda r: r.score, reverse=True):
            snapshot = result.detection.snapshot
            table.add_row(
                str(snapshot.pid),
                snapshot.username,
                snapshot.name,
                result.detection.detection_type,
                _severity_cell(result.severity),
                str(result.score),
                result.reason,
            )

        self.console.print(table)
