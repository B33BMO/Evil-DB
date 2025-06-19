from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
import sqlite3
from typing import List
app = FastAPI(title="EvilWatch API", version="0.1")




class ThreatCheckResponse(BaseModel):
    match: bool
    value: str
    category: Optional[str] = None
    source: Optional[str] = None
    severity: Optional[str] = None
    notes: Optional[str] = None

def query_threat_db(indicator_type: str, value: str) -> ThreatCheckResponse:
    conn = sqlite3.connect("/home/evil-db/evil-db/db/threats.db")
    cur = conn.cursor()
    cur.execute("SELECT category, source, severity, notes FROM threat_indicators WHERE type=? AND value=?", (indicator_type, value))
    row = cur.fetchone()
    conn.close()

    if row:
        return ThreatCheckResponse(match=True, value=value, category=row[0], source=row[1], severity=row[2], notes=row[3])
    else:
        return ThreatCheckResponse(match=False, value=value)

@app.get("/check", response_model=ThreatCheckResponse)
def check_threat(
    type: str = Query(..., regex="^(ip|email|domain)$"),
    value: str = Query(...)
):
    return query_threat_db(type, value)

@app.get("/list", response_model=List[ThreatCheckResponse])
def list_threats(limit: int = 100):
    conn = sqlite3.connect("/home/evil-db/evil-db/db/threats.db")
    cur = conn.cursor()
    cur.execute("SELECT value, category, source, severity, notes FROM threat_indicators LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()

    return [
        ThreatCheckResponse(
            match=True,
            value=row[0],
            category=row[1],
            source=row[2],
            severity=row[3],
            notes=row[4]
        )
        for row in rows
    ]

@app.get("/search", response_model=List[ThreatCheckResponse])
def search_threats(q: str, limit: int = 50):
    conn = get_db_connection()
    cur = conn.cursor()
    like_query = f"%{q}%"
    cur.execute("""
        SELECT value, category, source, severity, notes
        FROM threat_indicators
        WHERE value LIKE ? OR category LIKE ? OR source LIKE ? OR notes LIKE ?
        LIMIT ?
    """, (like_query, like_query, like_query, like_query, limit))
    rows = cur.fetchall()
    conn.close()
    return [
        ThreatCheckResponse(match=True, value=row[0], category=row[1], source=row[2], severity=row[3], notes=row[4])
        for row in rows
    ]