# ReportForge

**Version: 1.2.2**

A web-based security report writing tool with a fully custom template builder.

## Features

- **Custom Template Builder** — Create reusable templates with your own sections (Text, Table, Findings, Checklist) and custom fields
- **Report Editor** — Fill reports with Info, Sections, Findings, and Preview tabs; auto-saves as you type
- **Findings Manager** — Track vulnerabilities by severity (Critical → Info) and status (Open → Remediated)
- **Dashboard** — Overview of all reports with stats and quick access

## Quick Start

```bash
pip install -e .
reportforge serve
```

Open **http://127.0.0.1:8000** in your browser.

## Docker

```bash
docker compose up
```

## How to use

1. Go to **Templates** → **New Template**
2. Add sections — Text, Table, Findings, or Checklist
3. For each section, define custom fields (text, textarea, date, number, select)
4. Go to **Reports** → **New Report**, choose your template
5. Fill out the report in the editor — Info tab for metadata, Sections tab for template content, Findings tab for vulnerabilities
6. Use the **Preview** tab to review the formatted output

## Install via pipx

```bash
pipx install git+https://github.com/BrocktonPointSolutions/ReportForge.git
reportforge serve
```
