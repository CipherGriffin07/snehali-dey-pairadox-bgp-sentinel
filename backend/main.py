
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from detector import BGPDetector
import ipaddress
import storage

app = FastAPI(
    title="Pairadox BGP Sentinel",
    description="Explainable BGP Origin and Subprefix Anomaly Monitor",
    version="1.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

detector = BGPDetector()


class BGPAnnouncement(BaseModel):
    prefix: str
    origin_asn: int = Field(ge=0, le=4294967295)


@app.get("/")
def home():
    return {
        "project": "Pairadox BGP Sentinel",
        "status": "Running",
        "team": "Pairadox",
        "version": "1.1.0",
        "features": [
            "Origin Change Detection",
            "Subprefix Anomaly Detection",
            "Demo RPKI Validation",
            "Persistent SQLite Storage",
            "Explainable Security Alerts"
        ]
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "Pairadox BGP Sentinel API"
    }


@app.post("/analyze")
def analyze_route(data: BGPAnnouncement):
    try:
        ipaddress.ip_network(data.prefix, strict=True)

        return detector.analyze(
            data.prefix,
            data.origin_asn
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc)
        )


@app.get("/alerts")
def get_alerts():
    return detector.alerts


@app.get("/routes")
def get_routes():
    return detector.routes


@app.get("/stats")
def get_stats():
    alerts = detector.alerts

    return {
        "total_routes": len(detector.routes),
        "total_alerts": len(alerts),
        "origin_changes": sum(
            1 for a in alerts
            if a["type"] == "ORIGIN_CHANGE"
        ),
        "subprefix_anomalies": sum(
            1 for a in alerts
            if a["type"] == "SUBPREFIX_ANOMALY"
        ),
        "rpki_invalid": sum(
            1 for a in alerts
            if a["type"] == "RPKI_INVALID"
        ),
        "critical_alerts": sum(
            1 for a in alerts
            if a["severity"] == "CRITICAL"
        )
    }


@app.post("/reset")
def reset_data():
    global detector

    storage.clear()
    detector = BGPDetector()

    return {
        "message": "Demo data reset successfully",
        "status": "success"
    }
