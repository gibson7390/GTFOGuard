from rich.console import Console
from rich.table import Table

from validation.catalog import VALIDATION_SCENARIOS
from validation.harness import run_all, ScenarioResult


def _format_expected(result: ScenarioResult) -> str:
    if not result.scenario.expected:
        return "no actionable finding"
    return "\n".join(
        f"{e.detector} {e.severity}/{e.score}" for e in result.scenario.expected
    )


def _format_actual(result: ScenarioResult) -> str:
    lines = []
    for f in result.actionable:
        lines.append(f"{f.detector} {f.severity}/{f.score} ({f.matched_name})")
    if not result.actionable:
        lines.append("no actionable finding")
    for f in result.informational:
        lines.append(f"[dim]info: {f.detector} {f.severity}/{f.score} ({f.matched_name})[/dim]")
    return "\n".join(lines)


def main() -> None:
    console = Console()
    results = run_all(VALIDATION_SCENARIOS)

    table = Table(title="GTFOGuard Operational Validation Harness", show_lines=True)
    table.add_column("Scenario", style="bold")
    table.add_column("Kind")
    table.add_column("Expected (actionable)")
    table.add_column("Actual")
    table.add_column("Result", justify="center")

    for result in results:
        verdict = "[green]PASS[/green]" if result.passed else "[red]FAIL[/red]"
        table.add_row(
            result.scenario.name,
            result.scenario.kind,
            _format_expected(result),
            _format_actual(result),
            verdict,
        )

    console.print(table)

    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    false_positives = [(r, f) for r in results for f in r.false_positives]
    false_negatives = [(r, f) for r in results for f in r.false_negatives]
    informational = [(r, f) for r in results for f in r.informational]

    console.print(
        f"\n[bold]Summary:[/bold] {passed}/{len(results)} passed, {failed} failed  |  "
        f"actionable false positives: {len(false_positives)}  |  "
        f"false negatives: {len(false_negatives)}  |  "
        f"informational (LOW) findings: {len(informational)}"
    )

    if false_positives:
        console.print("\n[bold red]Actionable false positives:[/bold red]")
        for r, f in false_positives:
            console.print(f"  - {r.scenario.name}: {f.detector} {f.severity}/{f.score} ({f.matched_name})")

    if false_negatives:
        console.print("\n[bold red]False negatives:[/bold red]")
        for r, f in false_negatives:
            console.print(f"  - {r.scenario.name}: expected {f.detector} {f.severity}/{f.score} not produced")

    if informational:
        console.print("\n[bold yellow]Informational LOW findings (baseline noise):[/bold yellow]")
        for r, f in informational:
            console.print(f"  - {r.scenario.name}: {f.detector} {f.severity}/{f.score} ({f.matched_name})")


if __name__ == "__main__":
    main()
