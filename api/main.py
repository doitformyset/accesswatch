# Import FASTAPI
import datetime
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File        # FastAPI: creates the web app instance, Depends: Dependency injection for DB sessions, so you don't have to manually create and close sessions in each endpoint
from sqlalchemy.orm import Session
from pydantic import BaseModel              # Defines a schema for your API responses (and/or requests): Validates types, serializes Python to JSON, and powers your /docs with accurate field shapes
from typing import List, Dict, Optional     # a route returns a list of things (List[FindingOut]), a field is a dictionary (Dict[str, Any]), or a field may be optional (Optional[Dict])
import csv, io
from api.db import SessionLocal, Finding, Membership
from collections import Counter
from fastapi.responses import StreamingResponse, HTMLResponse, RedirectResponse
from starlette.templating import Jinja2Templates
from starlette.requests import Request

templates = Jinja2Templates(directory="templates")

# Add a response model so FastAPI knows the shape of what you return and can serialize SQLAlchemy objects cleanly
class FindingOut(BaseModel):
    id: int
    rule_id: str
    severity: str
    entity_type: str
    entity_name: str
    details: Optional[Dict]  = None 

    class Config:
        from_attributes = True  # Tells Pydantic to read SQLAlchemy objects

class SeedResult(BaseModel):
    message: str
    rows: int

class IngestResult(BaseModel):
    inserted: int

class RuleRunResult(BaseModel):
    rule_id: str
    created: int

class MembershipOut(BaseModel):
    source: str
    group_name: str
    member_name: str
    member_type: str

class MetricsOut(BaseModel):
    total_findings: int
    by_severity: Dict[str, int]  # e.g., {"CRITICAL": 5, "HIGH": 10}
    by_rule: Dict[str, int]      # e.g., {"AW-AD-001": 5, "AW-LNX-002": 10}

class RulesSummary(BaseModel):
    results: List[RuleRunResult]
    total_created: int

# Create the FastAPI app
app = FastAPI(title = "AccessWatch API", version = "1.0.0")

# Dependency to get DB session for each request
# Yields a session for the request, then closes it after. 
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def hello():
    return {
        "message": "Welcome to the AccessWatch API",
        "version": "1.0.0",
        "status": "success"
        }

@app.get("/findings", response_model=List[FindingOut])  # response_model: tells FastAPI what shape to expect in the response, and to validate/serialize it accordingly
def get_findings(db: Session = Depends(get_db)):            # Tells FastAPI to call get_db() for me before the endpoint runs, give me the db it yields, and clean it up after
    # Pull all findings from the "findings" table
    return db.query(Finding).all()

@app.get("/memberships", response_model=List[MembershipOut])
def get_memberships(db: Session = Depends(get_db)):
    rows = db.query(Membership).all()
    return [
        MembershipOut(
            source=r.source,
            group_name=r.group_name,
            member_name=r.member_name,
            member_type=r.member_type
        ) 
        for r in rows
    ]

@app.get("/metrics", response_model=MetricsOut)
def get_metrics(db: Session = Depends(get_db)):
    rows = db.query(Finding.rule_id, Finding.severity).all()
    by_rule = Counter(r[0] for r in rows)
    by_severity = Counter(r[1] for r in rows)
    return MetricsOut(
        total_findings=len(rows),
        by_rule=dict(by_rule),
        by_severity=dict(by_severity)
    )

@app.get("/ui/findings", response_class=HTMLResponse)
def ui_findings(request: Request, db: Session = Depends(get_db)):
    rows = db.query(Finding).order_by(Finding.severity.desc(), Finding.id.desc()).all()
    # Compute Simple Counts
    sev_counts = Counter(r.severity for r in rows)
    return templates.TemplateResponse(
        "findings.html",
        {
            "request": request,
            "findings": rows,
            "by_severity": dict(sev_counts),
            "updated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
    )

@app.get("/findings.csv")
def export_findings_csv(db: Session = Depends(get_db)):
    rows = db.query(Finding).order_by(Finding.id.asc()).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "rule_id", "severity", "entity_type", "entity_name", "group", "evidence", "source"])  # Header
    for r in rows:
        d = r.details or {}
        writer.writerow([
            r.id, r.rule_id, r.severity, r.entity_type, r.entity_name,
            d.get("group", ""), d.get("evidence", ""), d.get("source", ""),
        ])
    buf.seek(0)
    return StreamingResponse(buf, media_type="text/csv", headers={
        "Content-Disposition": 'attachment; filename="findings.csv"'
    })

@app.get("/ui/memberships", response_class=HTMLResponse)
def memberships_html(request: Request, db: Session = Depends(get_db)):
    rows = db.query(Membership).order_by(Membership.source, Membership.group_name, Membership.member_name).all()
    return templates.TemplateResponse(
        "memberships.html",
        {
            "request": request,
            "memberships": rows,
            "updated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }, 
    )

@app.get("/memberships_csv")
def export_memberships_csv(db: Session = Depends(get_db)):
    rows = db.query(Membership).order_by(Membership.source, Membership.group_name, Membership.member_name).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["source", "group_name", "member_name", "member_type"])  # Header
    for r in rows:
        w.writerow([r.source, r.group_name, r.member_name, r.member_type])
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="memberships.csv"'},
    )

@app.post("/seed-data", response_model=SeedResult)
def seed_data(db: Session = Depends(get_db)):
    # If we already have data, don't insert again
    try:
        count = db.query(Finding).count()
        if count > 0:
            return SeedResult(message="Already seeded", rows=count)

        rows = [
            Finding(
                rule_id="AW-AD-001",
                severity="CRITICAL",
                entity_type="user",
                entity_name="midcorp\\rita.patel",
                details={"group": "Domain Admins", "evidence": "direct_membership", "source": "AD"}
            ),
            Finding(
                rule_id="AW-LNX-002",
                severity="HIGH",
                entity_type="user",
                entity_name="john.smith",
                details={"group": "sudo", "evidence": "group_membership", "source": "LINUX"},
            ),
        ]
        db.add_all(rows)
        db.commit()
        return SeedResult(message="Seeded", rows=len(rows))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/ingest/memberships", response_model=IngestResult)
async def ingest_memberships(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Upload a CSV file with headers: source,group_name,member_name,member_type
    Example row: AD,Domain Admins,john.smith,user
    """
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files are supported.")
    
    content = (await file.read()).decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(content))

    required = {"source", "group_name", "member_name", "member_type"}
    if not required.issubset(set(reader.fieldnames or [])):
        raise HTTPException(status_code=422, detail=f"CSV must include columns: {sorted(required)}")

    to_insert = []
    seen = set()  # To track duplicates in the uploaded file
    
    for row in reader:
        
        key = (
            row["source"].strip(),
            row["group_name"].strip(),
            row["member_name"].strip(),
            row["member_type"].strip()
        )
        if key in seen:
            continue
        seen.add(key)

        exists = (
            db.query(Membership.id)
            .filter_by(
                source=key[0],
                group_name=key[1],
                member_name=key[2],
                member_type=key[3]
            ).first()
        )
        if exists:
            continue  # Skip existing records

        to_insert.append(
            Membership(
                source=key[0],
                group_name=key[1],
                member_name=key[2],
                member_type=key[3]
            )
        )

    if not to_insert:
        return IngestResult(inserted=0)
    
    db.add_all(to_insert)
    db.commit()
    return IngestResult(inserted=len(to_insert))

@app.post("/rules/run", response_model=RulesSummary)
def run_rules(db: Session = Depends(get_db)):  
    results: List[RuleRunResult] = []
    total = 0

    # Rule 1: AD Domain Admins (AW-AD-001)
    RULE_ID = "AW-AD-001"
    db.query(Finding).filter(Finding.rule_id == RULE_ID).delete()
    ad_hits = (
        db.query(Membership.member_name, Membership.member_type)
        .filter(Membership.source == "AD", Membership.group_name == "Domain Admins")
        .distinct()
        .all()
    )
    ad_rows = [
        Finding(
            rule_id=RULE_ID,
            severity="CRITICAL",
            entity_type=member_type,
            entity_name=member_name,
            details={"group": "Domain Admins", "evidence": "direct_membership", "source": "AD"}
        )
        for member_name, member_type in ad_hits
    ]
    if ad_rows:
        db.add_all(ad_rows)
        db.commit()
        results.append(RuleRunResult(rule_id=RULE_ID, created=len(ad_rows)))
        total += len(ad_rows)

    # Rule 2: LINUX sudo group (AW-LNX-002)
    RULE_LNX = "AW-LNX-002"
    db.query(Finding).filter(Finding.rule_id == RULE_LNX).delete()
    lnx_hits = (
        db.query(Membership.member_name, Membership.member_type)
        .filter(Membership.source == "LINUX", Membership.group_name == "sudo")
        .distinct()
        .all()
    )
    lnx_rows = [
        Finding(
            rule_id=RULE_LNX,
            severity="HIGH",
            entity_type=member_type,
            entity_name=member_name,
            details={"group": "sudo", "evidence": "group_membership", "source": "LINUX"}
        )
        for member_name, member_type in lnx_hits
    ]
    if lnx_rows:
        db.add_all(lnx_rows)
        db.commit()
        results.append(RuleRunResult(rule_id=RULE_LNX, created=len(lnx_rows)))
        total += len(lnx_rows)

    # Rule 3: AD Help Desk (AW-AD-002)
    RULE_HD = "AW-AD-002"
    db.query(Finding).filter(Finding.rule_id == RULE_HD).delete()
    help_hits = (
        db.query(Membership.member_name, Membership.member_type)
        .filter(Membership.source == "AD", Membership.group_name == "Help Desk")
        .distinct()
        .all()
    )
    help_rows = [
        Finding(
            rule_id=RULE_HD,
            severity="WARNING",
            entity_type=member_type,
            entity_name=member_name,
            details={"group": "Help Desk", "evidence": "direct_membership", "source": "AD"}
        )
        for member_name, member_type in help_hits
    ]
    if help_rows:
        db.add_all(help_rows)
        db.commit()
        results.append(RuleRunResult(rule_id=RULE_HD, created=len(help_rows)))
        total += len(help_rows)


    return RulesSummary(results=results, total_created=total)

@app.post("/ui/run-rules")
def ui_run_rules(db: Session = Depends(get_db)):
    _=run_rules(db)     # Reuse the existing function
    return RedirectResponse(url="/ui/findings", status_code=303)

@app.post("/ui/reset-all")
def ui_reset_all(db: Session = Depends(get_db)):
    # Same Logic as /debug/reset-all
    m = db.query(Membership).delete()
    f = db.query(Finding).delete()
    db.commit()
    return RedirectResponse(url="/ui/findings", status_code=303)

@app.delete("/debug/reset-all")
def reset_all(db: Session = Depends(get_db)):
    m = db.query(Membership).delete()
    f = db.query(Finding).delete()
    db.commit()
    return {"deleted_memberships": m, "deleted_findings": f}


"""@app.post("/rules/run")
def run_rules(db: Session = Depends(get_db)):
    
#    MVP Rule: AW-AD-001
#   Flag any memberships where source=AD, group_name="Domain Admins."
#  Clears prior findings before inserting new ones.
    

    RULE_ID = "AW-AD-001"

    #Clear prior findings for this rule (simple idempotency)
    db.query(Finding).filter(Finding.rule_id == RULE_ID).delete()

    hits = (
        db.query(Membership.member_name, Membership.member_type)
        .filter(Membership.source == "AD", Membership.group_name == "Domain Admins")
        .distinct()
        .all()
    )

    new_rows = []
    for member_name, member_type in hits: # tuples, not objects
        new_rows.append(
            Finding(
                rule_id=RULE_ID,
                severity="CRITICAL",
                entity_type=member_type,
                entity_name=member_name,
                details={"group": "Domain Admins", "evidence": "direct_membership", "source": "AD"}
            )
        )

    if new_rows:
        db.add_all(new_rows)
        db.commit()

    RULE_LNX = "AW-LNX-002"
    db.query(Finding).filter(Finding.rule_id == RULE_LNX).delete()

    lnx_hits = (
        db.query(Membership.member_name, Membership.member_type)
        .filter(Membership.source == "LINUX", Membership.group_name == "sudo")
        .distinct()
        .all()
    )

    lnx_rows = []
    for member_name, member_type in lnx_hits:   #tuples, not objects
        lnx_rows.append(
            Finding(
                rule_id=RULE_LNX,
                severity="HIGH",
                entity_type=member_type,
                entity_name=member_name,
                details={"group": "sudo", "evidence": "group_membership", "source": "LINUX"}
            )
        )
    if lnx_rows:
        db.add_all(lnx_rows)
        db.commit()

    return RuleRunResult(rule_id=RULE_ID, created=len(new_rows))
    """