import typer
import asyncio
import json
import rich
from rich.console import Console
from rich.table import Table
from apscan.core.context import ScanTarget
from apscan.core.orchestrator import ScanOrchestrator

app = typer.Typer()
console = Console()

@app.command()
def scan(
    target: str = typer.Option(None, help="URL to OpenAPI spec (json/yaml)"),
    curl: str = typer.Option(None, help="Single raw cURL command to scan"),
    har: str = typer.Option(None, help="Path to HAR file"),
    postman: str = typer.Option(None, help="Path to Postman Collection JSON"),
    list_file: str = typer.Option(None, help="Path to text file with URLs"),
    graphql: bool = typer.Option(False, help="Treat target as a GraphQL endpoint (enables introspection)"),
    auth_type: str = typer.Option(None, help="Auth type: 'apikey' or 'basic'"),
    token: str = typer.Option(None, help="API Key or Token"),
    header: str = typer.Option("X-API-Key", help="Header name for API Key"),
    username: str = typer.Option(None, help="Username for Basic Auth"),
    password: str = typer.Option(None, help="Password for Basic Auth"),
    ai_provider: str = typer.Option(None, help="AI Provider: 'gemini' or 'openai'"),
    ai_key: str = typer.Option(None, envvar=["GEMINI_API_KEY", "OPENAI_API_KEY"], help="AI API Key"),
    ai_model: str = typer.Option(None, help="Override AI Model name"),
    workflow: str = typer.Option(None, help="Path to workflow YAML file for stateful scans"),
    plugin_dir: str = typer.Option(None, help="Directory containing custom python rules (.py)")
):
    """
    Run an API security scan against the specified target.
    """
    if not any([target, curl, har, postman, list_file, workflow]):
        console.print("[bold red]Error: You must provide --target, --curl, --har, --postman, --list-file, or --workflow.[/bold red]")
        raise typer.Exit(code=1)

    t_str = target
    if curl: t_str = "cURL Input"
    if har: t_str = f"HAR File ({har})"
    if postman: t_str = f"Postman ({postman})"
    if list_file: t_str = f"List File ({list_file})"
    if workflow: t_str = f"Workflow ({workflow})"
    
    console.print(f"[bold green]Starting APScan against {t_str}[/bold green]")
    
    auth_config = None
    if auth_type:
        auth_config = {"type": auth_type.lower()}
        if auth_type.lower() == "apikey":
            auth_config["key"] = token
            auth_config["header"] = header
        elif auth_type.lower() == "basic":
            auth_config["username"] = username
            auth_config["password"] = password

    ai_config = None
    if ai_provider:
        auth_config = { # Fix: use ai_config dict
            "provider": ai_provider,
            "key": ai_key,
            "model": ai_model
        }

    scan_target = ScanTarget(
        url=target, 
        curl_command=curl, 
        har_file=har, 
        postman_file=postman,
        list_file=list_file,
        plugin_dir=plugin_dir,
        graphql=graphql,
        auth_config=auth_config,
        ai_config=ai_config
    )
    
    orchestrator = ScanOrchestrator(scan_target)
    
    async def run_scan():
        if workflow:
             await orchestrator.discover_apis() # Initialize context/http_client
             orchestrator.load_rules()
             await orchestrator.run_workflows([workflow])
             orchestrator.generate_report()
             return orchestrator.context.findings
        else:
             return await orchestrator.run()
    
    import asyncio
    findings = asyncio.run(run_scan())
    
    # Summary Table (CLI specific UX)
    if findings:
        table = Table(title="Scan Findings")
        table.add_column("Severity", style="red")
        table.add_column("Rule")
        table.add_column("Count")
        table.add_column("Affected Endpoints")
        
        # Group findings for cleaner CLI output
        from collections import defaultdict
        grouped_findings = defaultdict(list)
        for f in findings:
            grouped_findings[f.name].append(f)

        for rule_name, group in grouped_findings.items():
            first = group[0]
            endpoints = [f"{f.method.value} {f.endpoint}" for f in group]
            endpoint_str = ", ".join(endpoints[:3])
            if len(endpoints) > 3:
                endpoint_str += f" (+{len(endpoints)-3} more)"
            
            table.add_row(
                first.severity.value,
                rule_name, 
                str(len(group)), 
                endpoint_str
            )
            
        console.print(table)
        console.print(f"\n[bold]Reports generated (JSON & HTML).[/bold]")
        
        # CI/CD: Exit with 1 if HIGH or CRITICAL findings exist
        has_critical = any(f.severity.value in ["HIGH", "CRITICAL"] for f in findings)
        if has_critical:
            console.print("[bold red]Build failed: High severity vulnerabilities detected.[/bold red]")
            raise typer.Exit(code=1)
        
    else:
        console.print("[bold green]No vulnerabilities found![/bold green]")

if __name__ == "__main__":
    app()
