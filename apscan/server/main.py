from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
from apscan.server.models import ScanConfigRequest, ScanSubmissionResponse, ScanStatusResponse, ScanInputType
from apscan.server.manager import ScanManager
from apscan.core.context import Vulnerability

app = FastAPI(title="APScan API", version="0.1.0")

# Allow CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

manager = ScanManager.get_instance()

@app.on_event("startup")
async def startup_event():
    await manager.ensure_db()

@app.get("/")
def root():
    return {"message": "APScan Backend Ready", "docs": "/docs"}

@app.post("/api/scan", response_model=ScanSubmissionResponse)
async def start_scan(config: ScanConfigRequest):
    """Start a new scan."""
    scan_id = await manager.start_scan(config)
    return ScanSubmissionResponse(scan_id=scan_id, message="Scan started successfully")

@app.get("/api/scan/{scan_id}", response_model=ScanStatusResponse)
@app.get("/api/scan/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """Get the status of a specific scan."""
    status = await manager.get_status(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail="Scan not found")
    return status

@app.get("/api/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Get the findings of a completed scan."""
    results = await manager.get_results(scan_id)
    return results

@app.get("/api/scans", response_model=list[ScanStatusResponse])
async def get_scans_history():
    """Get history of all scans."""
    return await manager.get_history()

from fastapi.responses import HTMLResponse

@app.get("/api/scan/{scan_id}/report", response_class=HTMLResponse)
async def get_scan_report(scan_id: str):
    """Download HTML report."""
    content = await manager.generate_report(scan_id)
    if not content:
        raise HTTPException(status_code=404, detail="Scan not found")
    return content

from fastapi.responses import Response

@app.get("/api/scan/{scan_id}/report/pdf")
async def get_scan_report_pdf(scan_id: str):
    """Download PDF report."""
    pdf_bytes = await manager.generate_pdf_report(scan_id)
    if not pdf_bytes:
        raise HTTPException(status_code=404, detail="Scan not found or PDF generation failed")
    
    return Response(
        content=pdf_bytes, 
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=scan_report_{scan_id}.pdf"}
    )

@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan."""
    success = await manager.delete_scan(scan_id)
    if not success:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"message": "Scan deleted successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("apscan.server.main:app", host="0.0.0.0", port=8000, reload=True)
