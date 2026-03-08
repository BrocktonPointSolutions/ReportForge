from __future__ import annotations
import json, uuid, datetime as dt
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
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
