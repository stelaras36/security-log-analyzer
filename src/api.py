from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .database import (
    get_all_incidents,
    get_incident_status_history,
    get_incident_notes,
    update_incident_status,
    add_incident_note
)


app = FastAPI(
    title="Security Log Analyzer API",
    description="REST API for the Security Log Analyzer Mini SIEM",
    version="3.0.0"
)


class IncidentStatusUpdate(BaseModel):
    status: str
    analyst: str = "system"


class IncidentNoteCreate(BaseModel):
    note: str
    analyst: str = "system"


def incident_to_dict(incident):
    return {
        "id": incident[0],
        "ip_address": incident[1],
        "failed_attempts": incident[2],
        "targeted_users": incident[3],
        "risk_level": incident[4],
        "alert": incident[5],
        "detection_type": incident[6],
        "mitre_technique_id": incident[7],
        "mitre_technique_name": incident[8],
        "mitre_tactic": incident[9],
        "status": incident[10],
        "analyst_notes": incident[11],
        "updated_at": incident[12],
        "created_at": incident[13],
        "incident_fingerprint": incident[14],
        "event_start": incident[15],
        "event_end": incident[16]
    }


def incident_exists(incident_id):
    incidents = get_all_incidents()

    return any(
        incident[0] == incident_id
        for incident in incidents
    )


@app.get("/")
def root():
    return {
        "message": "Security Log Analyzer API",
        "status": "running",
        "version": "3.0.0"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.get("/incidents")
def get_incidents():
    incidents = get_all_incidents()

    results = [
        incident_to_dict(incident)
        for incident in incidents
    ]

    return {
        "count": len(results),
        "incidents": results
    }


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: int):
    incidents = get_all_incidents()

    for incident in incidents:
        if incident[0] == incident_id:
            return incident_to_dict(incident)

    raise HTTPException(
        status_code=404,
        detail="Incident not found"
    )


@app.get("/incidents/{incident_id}/status-history")
def get_status_history(incident_id: int):
    if not incident_exists(incident_id):
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    history = get_incident_status_history(
        incident_id
    )

    results = []

    for entry in history:
        results.append({
            "id": entry[0],
            "incident_id": entry[1],
            "old_status": entry[2],
            "new_status": entry[3],
            "analyst": entry[4],
            "changed_at": entry[5]
        })

    return {
        "incident_id": incident_id,
        "count": len(results),
        "status_history": results
    }


@app.get("/incidents/{incident_id}/notes")
def get_notes(incident_id: int):
    if not incident_exists(incident_id):
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    notes = get_incident_notes(
        incident_id
    )

    results = []

    for entry in notes:
        results.append({
            "id": entry[0],
            "incident_id": entry[1],
            "note": entry[2],
            "analyst": entry[3],
            "created_at": entry[4]
        })

    return {
        "incident_id": incident_id,
        "count": len(results),
        "notes": results
    }


@app.post("/incidents/{incident_id}/notes")
def create_note(
    incident_id: int,
    note_data: IncidentNoteCreate
):
    if not note_data.note.strip():
        raise HTTPException(
            status_code=400,
            detail="Note cannot be empty"
        )

    added = add_incident_note(
        incident_id,
        note_data.note,
        note_data.analyst
    )

    if not added:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return {
        "message": "Analyst note added successfully",
        "incident_id": incident_id,
        "note": note_data.note.strip(),
        "analyst": (
            note_data.analyst.strip()
            or "system"
        )
    }


@app.patch("/incidents/{incident_id}/status")
def change_incident_status(
    incident_id: int,
    update: IncidentStatusUpdate
):
    try:
        updated = update_incident_status(
            incident_id,
            update.status,
            update.analyst
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    if not updated:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return {
        "message": "Incident status updated successfully",
        "incident_id": incident_id,
        "status": update.status.strip().upper(),
        "analyst": update.analyst
    }