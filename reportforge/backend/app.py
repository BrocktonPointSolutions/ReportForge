from __future__ import annotations
import json, uuid, datetime as dt
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import select

from .db import engine, SessionLocal, Base
from .models import Report, Template, Finding

app = FastAPI(
    title='ReportForge API',
    version='1.0.0')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=False,
    allow_methods=['*'],
    allow_headers=['*'],
)

_FRONTEND_DIR = (
    Path(__file__).resolve()
    .parents[1] / 'frontend'
).resolve()

def _migrate_findings_cols():
    cols = [
        ('discussion', 'TEXT'),
        ('refs', 'TEXT'),
    ]
    from sqlalchemy import text
    with engine.connect() as con:
        for col, typ in cols:
            sql = (
                'ALTER TABLE findings'
                ' ADD COLUMN '
                + col + ' ' + typ
                + ' DEFAULT ""'
            )
            try:
                con.execute(text(sql))
                con.commit()
            except Exception:
                pass

@app.on_event('startup')
def _startup():
    from reportforge.utils import get_db_path
    import logging
    logging.basicConfig(level=logging.INFO)
    logging.getLogger('reportforge').info(
        'DB: %s', get_db_path()
    )
    Base.metadata.create_all(bind=engine)
    _migrate_findings_cols()

@app.get('/', response_class=HTMLResponse)
def serve_frontend():
    return (
        _FRONTEND_DIR / 'index.html'
    ).read_text(encoding='utf-8')

def _ts(d: dt.datetime) -> str:
    return (
        d.replace(microsecond=0)
        .isoformat() + 'Z'
    )

def _now_iso() -> str:
    return (
        dt.datetime.utcnow()
        .replace(microsecond=0)
        .isoformat() + 'Z'
    )

@app.get('/api/health')
def health():
    from reportforge.utils import get_db_path
    return {
        'ok': True,
        'time': _now_iso(),
        'db': str(get_db_path()),
    }

class ReportCreate(BaseModel):
    title: str = 'Untitled Report'
    org: str = ''
    report_type: str = Field(
        default='Security Assessment',
        alias='type')
    classification: str = 'Confidential'
    assessment_date: str = Field(
        default='', alias='date')
    authors: str = ''
    template_id: Optional[str] = None
    model_config = {
        'populate_by_name': True}

class ReportUpdate(BaseModel):
    title: Optional[str] = None
    org: Optional[str] = None
    report_type: Optional[str] = Field(
        default=None, alias='type')
    classification: Optional[str] = None
    assessment_date: Optional[str] = Field(
        default=None, alias='date')
    authors: Optional[str] = None
    status: Optional[str] = None
    data: Optional[dict[str, Any]] = None
    model_config = {
        'populate_by_name': True}

class FindingCreate(BaseModel):
    report_id: Optional[str] = None
    title: str = ''
    severity: str = 'Medium'
    status: str = 'open'
    description: str = ''
    discussion: str = ''
    recommendation: str = ''
    refs: str = ''
    cvss: Optional[float] = None

class FindingUpdate(BaseModel):
    report_id: Optional[str] = None
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None
    discussion: Optional[str] = None
    recommendation: Optional[str] = None
    refs: Optional[str] = None
    cvss: Optional[float] = None

class TemplateCreate(BaseModel):
    name: str
    description: str = ''
    sections: list[dict[str, Any]] = []

class TemplateUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    sections: Optional[
        list[dict[str, Any]]] = None

@app.get('/api/reports')
def list_reports(
    status: Optional[str] = None):
    with SessionLocal() as db:
        stmt = select(Report).order_by(
            Report.updated_at.desc())
        if status:
            stmt = stmt.where(
                Report.status == status)
        rows = (
            db.execute(stmt)
            .scalars().all())
        return [_report_out(r) for r in rows]

@app.post('/api/reports', status_code=201)
def create_report(payload: ReportCreate):
    rid = str(uuid.uuid4())
    init: dict[str, Any] = {
        'report': {
            'title': payload.title,
            'org': payload.org,
            'type': payload.report_type,
            'classification':
                payload.classification,
            'date': payload.assessment_date,
            'authors': payload.authors,
            'summary': '', 'scope': '',
        },
        'sections': [], 'findings': [],
    }
    if payload.template_id:
        with SessionLocal() as db:
            t = db.get(
                Template, payload.template_id)
            if t:
                tmpl = json.loads(
                    t.template_json or '{}')
                init['sections'] = (
                    tmpl.get('sections', []))
                init['template_id'] = (
                    payload.template_id)
                init['template_name'] = t.name
    with SessionLocal() as db:
        r = Report(
            id=rid,
            title=(
                payload.title.strip()
                or 'Untitled Report'),
            org=payload.org,
            report_type=payload.report_type,
            classification=(
                payload.classification),
            assessment_date=(
                payload.assessment_date),
            authors=payload.authors,
            status='draft',
            data_json=json.dumps(init),
        )
        db.add(r); db.commit()
    return {'id': rid}

@app.get('/api/reports/{rid}')
def get_report(rid: str):
    with SessionLocal() as db:
        stmt = select(Report).where(
            Report.id == rid)
        r = (
            db.execute(stmt)
            .scalar_one_or_none())
        if not r:
            raise HTTPException(
                404,
                f'Report not found: {rid!r}')
        return _report_out(r, include_data=True)

@app.put('/api/reports/{rid}')
def update_report(
    rid: str, payload: ReportUpdate):
    with SessionLocal() as db:
        stmt = select(Report).where(
            Report.id == rid)
        r = (
            db.execute(stmt)
            .scalar_one_or_none())
        if not r:
            raise HTTPException(
                404,
                f'Report not found: {rid!r}')
        if payload.title is not None:
            r.title = (
                payload.title.strip() or r.title)
        if payload.org is not None:
            r.org = payload.org
        if payload.report_type is not None:
            r.report_type = payload.report_type
        if payload.classification is not None:
            r.classification = (
                payload.classification)
        if payload.assessment_date is not None:
            r.assessment_date = (
                payload.assessment_date)
        if payload.authors is not None:
            r.authors = payload.authors
        if payload.status is not None:
            r.status = payload.status
        if payload.data is not None:
            rep = payload.data.get(
                'report', {})
            if rep.get('title'):
                r.title = rep['title']
            if rep.get('org') is not None:
                r.org = rep['org']
            r.data_json = json.dumps(
                payload.data)
        r.updated_at = dt.datetime.utcnow()
        db.add(r)
        db.commit()
        db.refresh(r)
        return {
            'ok': True,
            'updated_at': _ts(r.updated_at)
        }

@app.delete('/api/reports/{rid}')
def delete_report(rid: str):
    with SessionLocal() as db:
        r = db.get(Report, rid)
        if not r:
            raise HTTPException(
                404, 'Report not found')
        db.delete(r)
        db.commit()
    return {'ok': True}

def _report_out(
    r: Report,
    include_data: bool = False) -> dict:
    out = {
        'id': r.id,
        'title': r.title,
        'org': r.org,
        'type': r.report_type,
        'classification': r.classification,
        'date': r.assessment_date,
        'authors': r.authors,
        'status': r.status,
        'created_at': _ts(r.created_at),
        'updated_at': _ts(r.updated_at),
    }
    if include_data:
        try:
            out['data'] = json.loads(
                r.data_json or '{}')
        except:
            out['data'] = {}
    return out

@app.get('/api/findings')
def list_findings(
    report_id: Optional[str] = None):
    with SessionLocal() as db:
        stmt = select(Finding).order_by(
            Finding.updated_at.desc())
        if report_id:
            stmt = stmt.where(
                Finding.report_id == report_id)
        rows = (
            db.execute(stmt)
            .scalars().all())
        return [_finding_out(f) for f in rows]

@app.post('/api/findings', status_code=201)
def create_finding(
    payload: FindingCreate):
    fid = str(uuid.uuid4())
    with SessionLocal() as db:
        f = Finding(
            id=fid,
            report_id=payload.report_id,
            title=payload.title,
            severity=payload.severity,
            status=payload.status,
            description=payload.description,
            discussion=payload.discussion,
            recommendation=(
                payload.recommendation),
            refs=payload.refs,
            cvss=payload.cvss,
        )
        db.add(f)
        db.commit()
        db.refresh(f)
        return _finding_out(f)

@app.get('/api/findings/{fid}')
def get_finding(fid: str):
    with SessionLocal() as db:
        f = db.get(Finding, fid)
        if not f:
            raise HTTPException(
                404, 'Finding not found')
        return _finding_out(f)

@app.put('/api/findings/{fid}')
def update_finding(
    fid: str, payload: FindingUpdate):
    with SessionLocal() as db:
        f = db.get(Finding, fid)
        if not f:
            raise HTTPException(
                404, 'Finding not found')
        if payload.report_id is not None:
            f.report_id = payload.report_id
        if payload.title is not None:
            f.title = payload.title
        if payload.severity is not None:
            f.severity = payload.severity
        if payload.status is not None:
            f.status = payload.status
        if payload.description is not None:
            f.description = payload.description
        if payload.discussion is not None:
            f.discussion = payload.discussion
        if payload.recommendation is not None:
            f.recommendation = (
                payload.recommendation)
        if payload.refs is not None:
            f.refs = payload.refs
        if payload.cvss is not None:
            f.cvss = payload.cvss
        f.updated_at = dt.datetime.utcnow()
        db.add(f)
        db.commit()
        db.refresh(f)
        return _finding_out(f)

@app.delete('/api/findings/{fid}')
def delete_finding(fid: str):
    with SessionLocal() as db:
        f = db.get(Finding, fid)
        if not f:
            raise HTTPException(
                404, 'Finding not found')
        db.delete(f)
        db.commit()
    return {'ok': True}

def _finding_out(f: Finding) -> dict:
    return {
        'id': f.id,
        'report_id': f.report_id,
        'title': f.title,
        'severity': f.severity,
        'status': f.status,
        'description': f.description,
        'discussion': f.discussion,
        'recommendation': f.recommendation,
        'refs': f.refs,
        'cvss': f.cvss,
        'created_at': _ts(f.created_at),
        'updated_at': _ts(f.updated_at),
    }

@app.get('/api/templates')
def list_templates():
    with SessionLocal() as db:
        rows = (
            db.execute(
                select(Template).order_by(
                    Template.updated_at.desc()))
            .scalars().all())
        return [_template_out(t) for t in rows]

@app.post('/api/templates', status_code=201)
def create_template(payload: TemplateCreate):
    tid = str(uuid.uuid4())
    with SessionLocal() as db:
        t = Template(
            id=tid,
            name=(
                payload.name.strip()
                or 'Untitled Template'),
            description=payload.description,
            template_json=json.dumps(
                {'sections': payload.sections}),
        )
        db.add(t)
        db.commit()
    return {'id': tid}

@app.get('/api/templates/{tid}')
def get_template(tid: str):
    with SessionLocal() as db:
        t = db.get(Template, tid)
        if not t:
            raise HTTPException(
                404, 'Template not found')
        return _template_out(t, include_data=True)

@app.put('/api/templates/{tid}')
def update_template(
    tid: str, payload: TemplateUpdate):
    with SessionLocal() as db:
        t = db.get(Template, tid)
        if not t:
            raise HTTPException(
                404, 'Template not found')
        if payload.name is not None:
            t.name = (
                payload.name.strip() or t.name)
        if payload.description is not None:
            t.description = payload.description
        if payload.sections is not None:
            existing = json.loads(
                t.template_json or '{}')
            existing['sections'] = (
                payload.sections)
            t.template_json = json.dumps(
                existing)
        t.updated_at = dt.datetime.utcnow()
        db.add(t)
        db.commit()
        db.refresh(t)
        return {
            'ok': True,
            'updated_at': _ts(t.updated_at)
        }

@app.delete('/api/templates/{tid}')
def delete_template(tid: str):
    with SessionLocal() as db:
        t = db.get(Template, tid)
        if not t:
            raise HTTPException(
                404, 'Template not found')
        db.delete(t)
        db.commit()
    return {'ok': True}

def _template_out(
    t: Template,
    include_data: bool = False) -> dict:
    out = {
        'id': t.id,
        'name': t.name,
        'description': t.description,
        'created_at': _ts(t.created_at),
        'updated_at': _ts(t.updated_at),
    }
    if include_data:
        try:
            d = json.loads(
                t.template_json or '{}')
            out['sections'] = d.get(
                'sections', [])
        except:
            out['sections'] = []
    return out

def _build_report_html(r, findings):
    t = r.title or 'Report'
    esc = lambda s: (
        str(s)
        .replace('&','&amp;')
        .replace('<','&lt;')
        .replace('>','&gt;')
    )
    parts = [
        '<!DOCTYPE html>',
        '<html><head>',
        '<meta charset="UTF-8">',
        '<title>' + esc(t) + '</title>',
        '<style>',
        'body{font-family:Arial,sans-serif;',
        'margin:40px;color:#1a1d27}',
        'h1{font-size:24px;margin-bottom:8px}',
        'h2{font-size:18px;margin-top:32px;',
        'border-bottom:2px solid #4f6ef7;',
        'padding-bottom:4px}',
        '.meta{color:#555;margin-bottom:24px}',
        '.finding{border:1px solid #ccc;',
        'border-radius:6px;padding:16px;',
        'margin-bottom:16px}',
        '.sev{display:inline-block;',
        'padding:2px 8px;border-radius:4px;',
        'font-size:11px;font-weight:700;',
        'margin-left:8px}',
        '.critical{background:#d32f2f;color:#fff}',
        '.high{background:#f57c00;color:#fff}',
        '.medium{background:#f9a825;color:#000}',
        '.low{background:#388e3c;color:#fff}',
        '.info{background:#0288d1;color:#fff}',
        '.sec-content{margin:8px 0 16px 0;',
        'line-height:1.6}',
        '</style></head><body>',
    ]
    parts.append(
        '<h1>' + esc(t) + '</h1>')
    meta = []
    d = json.loads(r.data_json or '{}')
    if r.org:
        meta.append('Client: ' + esc(r.org))
    if r.assessment_date:
        meta.append(
            'Date: ' + esc(r.assessment_date))
    if r.authors:
        meta.append(
            'Authors: ' + esc(r.authors))
    if meta:
        parts.append(
            '<p class="meta">' +
            ' | '.join(meta) + '</p>')
    secs = d.get('sections', [])
    for sec in secs:
        parts.append(
            '<h2>' + esc(sec.get(
            'title','')) + '</h2>')
        content = sec.get('content','')
        if content:
            parts.append(
                '<div class="sec-content">'
                + content + '</div>')
    if findings:
        parts.append(
            '<h2>Findings (' +
            str(len(findings)) + ')</h2>')
        for f in findings:
            sev = (f.get('severity')
                   or 'info').lower()
            parts.append(
                '<div class="finding">')
            parts.append(
                '<b>' + esc(f.get(
                'title','')) + '</b>'
                + '<span class="sev '
                + sev + '">' + sev
                + '</span>')
            for lbl, key in [
                ('Observation','description'),
                ('Discussion','discussion'),
                ('Recommendations',
                 'recommendation'),
                ('References','refs'),
            ]:
                val = f.get(key,'')
                if val:
                    parts.append(
                        '<p><b>' + lbl
                        + ':</b></p>'
                        + '<div>' + val
                        + '</div>')
            parts.append('</div>')
    parts.append('</body></html>')
    return '\n'.join(parts)

def _get_report_for_export(rid):
    with SessionLocal() as db:
        r = db.get(Report, rid)
        if not r:
            raise HTTPException(
                404, 'Report not found')
        d = json.loads(
            r.data_json or '{}')
        findings = d.get('findings', [])
        return r, findings

@app.get('/api/reports/{rid}/export/html')
def export_html(rid: str):
    r, findings = _get_report_for_export(
        rid)
    html = _build_report_html(r, findings)
    fname = (r.title or 'report')
    fname = fname.replace(' ', '_')
    fname = fname + '.html'
    return Response(
        content=html,
        media_type='text/html',
        headers={
            'Content-Disposition':
            'attachment; filename="' +
            fname + '"'
        }
    )

@app.get('/api/reports/{rid}/export/pdf')
def export_pdf(rid: str):
    r, findings = _get_report_for_export(
        rid)
    html = _build_report_html(r, findings)
    try:
        from weasyprint import HTML
        pdf = HTML(
            string=html
        ).write_pdf()
    except Exception as e:
        raise HTTPException(
            500,
            'PDF generation failed: '
            + str(e))
    fname = (r.title or 'report')
    fname = fname.replace(' ', '_')
    fname = fname + '.pdf'
    return Response(
        content=pdf,
        media_type='application/pdf',
        headers={
            'Content-Disposition':
            'attachment; filename="' +
            fname + '"'
        }
    )

def _add_html_to_docx(doc, html, base_heading=2):
    import re, base64, io as _io
    from bs4 import BeautifulSoup, NavigableString, Tag
    from docx.shared import Pt, RGBColor
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement
    BLOCK_TAGS = {'p','div','h1','h2','h3','h4',
                  'h5','h6','ul','ol','li','br',
                  'blockquote','pre'}
    H_MAP = {'h1': base_heading,
             'h2': base_heading,
             'h3': base_heading+1,
             'h4': base_heading+2,
             'h5': base_heading+2,
             'h6': base_heading+3}
    def parse_color(style_str):
        m = re.search(r'colors*:s*#([0-9a-fA-F]{6})', style_str or '')
        if m:
            h = m.group(1)
            return RGBColor(int(h[0:2],16),int(h[2:4],16),int(h[4:6],16))
        m2 = re.search(r'colors*:s*rgb((d+),s*(d+),s*(d+))', style_str or '')
        if m2:
            return RGBColor(int(m2.group(1)),int(m2.group(2)),int(m2.group(3)))
        return None
    def add_run_from_node(para, node, bold=False, italic=False, color=None):
        if isinstance(node, NavigableString):
            txt = str(node)
            if not txt:
                return
            run = para.add_run(txt)
            run.bold = bold
            run.italic = italic
            if color:
                run.font.color.rgb = color
            return
        if not isinstance(node, Tag):
            return
        tag = node.name.lower() if node.name else ''
        new_bold = bold or tag in ('b','strong')
        new_italic = italic or tag in ('i','em')
        new_color = color
        style_str = node.get('style','')
        c = parse_color(style_str)
        if c:
            new_color = c
        if tag == 'img':
            src = node.get('src','')
            if src.startswith('data:image'):
                try:
                    header, b64data = src.split(',',1)
                    img_bytes = base64.b64decode(b64data)
                    img_stream = _io.BytesIO(img_bytes)
                    from docx.shared import Inches
                    run = para.add_run()
                    run.add_picture(img_stream, width=Inches(4))
                except Exception:
                    pass
            return
        for child in node.children:
            add_run_from_node(para, child, new_bold, new_italic, new_color)
    def process_block(node):
        if isinstance(node, NavigableString):
            txt = str(node).strip()
            if txt:
                doc.add_paragraph(txt)
            return
        if not isinstance(node, Tag):
            return
        tag = node.name.lower() if node.name else ''
        if tag in H_MAP:
            doc.add_heading(node.get_text(), H_MAP[tag])
            return
        if tag == 'img':
            src = node.get('src','')
            if src.startswith('data:image'):
                try:
                    header, b64data = src.split(',',1)
                    img_bytes = base64.b64decode(b64data)
                    img_stream = _io.BytesIO(img_bytes)
                    from docx.shared import Inches
                    p = doc.add_paragraph()
                    run = p.add_run()
                    run.add_picture(img_stream, width=Inches(4))
                except Exception:
                    pass
            return
        if tag in ('ul','ol'):
            list_style = 'List Bullet' if tag=='ul' else 'List Number'
            for li in node.find_all('li', recursive=False):
                p = doc.add_paragraph(style=list_style)
                for child in li.children:
                    add_run_from_node(p, child)
            return
        if tag in ('p','div','blockquote','pre'):
            has_block = any(
                isinstance(c, Tag) and c.name and
                c.name.lower() in BLOCK_TAGS
                for c in node.children)
            if has_block:
                for child in node.children:
                    process_block(child)
            else:
                p = doc.add_paragraph()
                for child in node.children:
                    add_run_from_node(p, child)
            return
        if tag == 'br':
            doc.add_paragraph()
            return
        for child in node.children:
            process_block(child)
    soup = BeautifulSoup(html, 'html.parser')
    for child in soup.children:
        process_block(child)


@app.get('/api/reports/{rid}/export/docx')
def export_docx(rid: str):
    r, findings = _get_report_for_export(
        rid)
    try:
        import io
        from docx import Document
        from bs4 import BeautifulSoup
        doc = Document()
        doc.add_heading(
            r.title or 'Report', 0)
        d = json.loads(
            r.data_json or '{}')
        meta_lines = []
        if r.org:
            meta_lines.append(
                'Client: ' + r.org)
        if r.assessment_date:
            meta_lines.append(
                'Date: ' + r.assessment_date)
        if r.authors:
            meta_lines.append(
                'Authors: ' + r.authors)
        for ml in meta_lines:
            doc.add_paragraph(ml)
        secs = d.get('sections', [])
        for sec in secs:
            doc.add_heading(
                sec.get('title',''), 1)
            content = sec.get('content','')
            if content:
                _add_html_to_docx(
                    doc, content,
                    base_heading=2)
        if findings:
            doc.add_heading(
                'Findings', 1)
            for f in findings:
                title = f.get('title','')
                sev = f.get('severity','')
                doc.add_heading(
                    title + ' [' + sev + ']', 2)
                for lbl, key in [
                  ('Observation','description'),
                  ('Discussion','discussion'),
                  ('Recommendations',
                   'recommendation'),
                  ('References','refs'),
                ]:
                    html_val = f.get(key,'')
                    if not html_val:
                        continue
                    p2 = doc.add_paragraph()
                    p2.add_run(
                        lbl + ':'
                    ).bold = True
                    _add_html_to_docx(
                        doc, html_val,
                        base_heading=3)
        buf = io.BytesIO()
        doc.save(buf)
        buf.seek(0)
        data = buf.read()
    except Exception as e:
        raise HTTPException(
            500,
            'DOCX generation failed: '
            + str(e))
    fname = (r.title or 'report')
    fname = fname.replace(' ', '_')
    fname = fname + '.docx'
    ct = (
        'application/vnd.openxmlformats'
        '-officedocument'
        '.wordprocessingml.document'
    )
    return Response(
        content=data,
        media_type=ct,
        headers={
            'Content-Disposition':
            'attachment; filename="' +
            fname + '"'
        }
    )
