from __future__ import annotations
import typer
import uvicorn
from reportforge.utils import ensure_home, get_db_path

cli = typer.Typer(add_completion=False, help="ReportForge")

@cli.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind host"),
    port: int = typer.Option(8000, help="Bind port"),
):
    """Start the ReportForge web server."""
    ensure_home()
    typer.echo(f"ReportForge running at http://{host}:{port}")
    uvicorn.run("reportforge.backend.app:app", host=host, port=port, reload=False)

@cli.command()
def init():
    """Initialize the workspace."""
    home = ensure_home()
    typer.echo(f"Workspace: {home}")
    typer.echo(f"Database:  {get_db_path()}")

if __name__ == "__main__":
    cli()
