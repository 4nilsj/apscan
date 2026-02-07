import asyncio
import uuid
import tempfile
import os
import json
from typing import Dict, List, Optional
from sqlalchemy import select, desc
from apscan.server.models import ScanConfigRequest, ScanStatusResponse, ScanState, ScanInputType
from apscan.core.context import ScanTarget, Vulnerability
from apscan.core.orchestrator import ScanOrchestrator
from apscan.server.db import AsyncSessionLocal, init_db
from apscan.server.db_models import DBScan, DBFinding

class ScanManager:
    _instance = None
    _tasks = set() # Keep references to background tasks

    def __init__(self):
        pass

    @classmethod
    def get_instance(cls):
        if not cls._instance:
            cls._instance = ScanManager()
        return cls._instance

    async def ensure_db(self):
         await init_db()

    async def start_scan(self, config: ScanConfigRequest) -> str:
        scan_id = str(uuid.uuid4())
        
        async with AsyncSessionLocal() as session:
            db_scan = DBScan(
                id=scan_id, 
                status="pending",
                message="Initialized",
                input_config=config.model_dump()
            )
            session.add(db_scan)
            await session.commit()

        # Start background task
        task = asyncio.create_task(self._run_scan(scan_id, config))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        
        return scan_id

    async def _run_scan(self, scan_id: str, config: ScanConfigRequest):
        # Update Status to Running
        async with AsyncSessionLocal() as session:
            stmt = select(DBScan).where(DBScan.id == scan_id)
            result = await session.execute(stmt)
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = "running"
                scan.message = "Running scan..."
                await session.commit()
        
        temp_files = []
        try:
            # Reconstruct Target
            auth_config = None
            if config_auth := config.auth_type:
                if config_auth == "apikey":
                     auth_config = {"type": "apikey", "key": config.auth_key, "header": config.auth_header}
                elif config_auth == "basic":
                     auth_config = {"type": "basic", "username": config.auth_username, "password": config.auth_password}

            ai_config = None
            if config.ai_provider:
                ai_config = {
                    "provider": config.ai_provider,
                    "key": config.ai_key,
                    "model": config.ai_model
                }

            target_url = config.target_url
            curl_cmd = config.curl_command
            har_file = None
            postman_file = None
            list_file = None
            
            if config.file_content:
                suffix = ""
                if config.input_type == ScanInputType.HAR: suffix = ".har"
                elif config.input_type == ScanInputType.POSTMAN: suffix = ".json"
                elif config.input_type == ScanInputType.LIST: suffix = ".txt"
                elif config.input_type == ScanInputType.OPENAPI: suffix = ".json"
                elif config.input_type == ScanInputType.WORKFLOW: suffix = ".yaml"
                
                with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as tmp:
                    tmp.write(config.file_content)
                    tmp_path = tmp.name
                    temp_files.append(tmp_path)
                
                if config.input_type == ScanInputType.HAR: har_file = tmp_path
                elif config.input_type == ScanInputType.POSTMAN: postman_file = tmp_path
                elif config.input_type == ScanInputType.LIST: list_file = tmp_path
                elif config.input_type == ScanInputType.OPENAPI: target_url = tmp_path
                # Workflow file is handled separately below

            scan_target = ScanTarget(
                url=target_url,
                curl_command=curl_cmd,
                har_file=har_file,
                postman_file=postman_file,
                list_file=list_file,
                graphql=config.graphql,
                auth_config=auth_config,
                ai_config=ai_config
            )

            orchestrator = ScanOrchestrator(scan_target)
            
            if config.input_type == ScanInputType.WORKFLOW and config.file_content:
                # Use the temp file we created
                await orchestrator.discover_apis() # Init context/http
                orchestrator.load_rules()
                # Run the workflow from the temp file path we saved in temp_files?
                # We need to find which temp file corresponds to workflow. 
                # Actually, simpler: just create it specifically or track it.
                # In previous block we appended to temp_files but didn't assign to specific var for workflow.
                # Let's fix that logic slightly or just find the one ending in yaml? 
                # Better: assign `workflow_file = tmp_path` in previous block.
                # Since I can't easily edit previous block efficiently again, I'll filter temp_files.
                workflow_file = next((f for f in temp_files if f.endswith('.yaml')), None)
                if workflow_file:
                     await orchestrator.run_workflows([workflow_file])
                     orchestrator.generate_report()
                     findings = orchestrator.context.findings
                else: 
                     findings = []
            else:
                findings = await orchestrator.run()
            
            endpoints_count = 0
            if orchestrator.context:
                endpoints_count = len(orchestrator.context.endpoints)

            # Save Findings and Update Status
            async with AsyncSessionLocal() as session:
                stmt = select(DBScan).where(DBScan.id == scan_id)
                result = await session.execute(stmt)
                scan = result.scalar_one_or_none()
                if scan:
                    scan.status = "completed"
                    scan.message = "Scan completed successfully."
                    scan.endpoints_count = endpoints_count
                    
                    for f in findings:
                        db_finding = DBFinding(
                            scan_id=scan.id,
                            severity=f.severity.value,
                            rule_id=f.rule_id,
                            name=f.name,
                            description=f.description,
                            endpoint=f.endpoint,
                            method=f.method.value,
                            evidence=f.evidence,
                            recommendation=f.recommendation,
                            reproduce_curl=f.reproduce_curl,
                            request_details=f.request_details,
                            response_details=f.response_details
                        )
                        session.add(db_finding)
                    
                    await session.commit()

        except Exception as e:
            import traceback
            traceback.print_exc()
            async with AsyncSessionLocal() as session:
                stmt = select(DBScan).where(DBScan.id == scan_id)
                result = await session.execute(stmt)
                scan = result.scalar_one_or_none()
                if scan:
                    scan.status = "failed"
                    scan.message = f"Scan failed: {str(e)}"
                    await session.commit()
        finally:
            for f in temp_files:
                try:
                    if os.path.exists(f): os.remove(f)
                except: pass

    async def get_status(self, scan_id: str) -> Optional[ScanStatusResponse]:
        async with AsyncSessionLocal() as session:
            stmt = select(DBScan).where(DBScan.id == scan_id)
            result = await session.execute(stmt)
            scan = result.scalar_one_or_none()
            
            if not scan:
                return None
            
            from sqlalchemy import func
            count_stmt = select(func.count()).select_from(DBFinding).where(DBFinding.scan_id == scan_id)
            count_res = await session.execute(count_stmt)
            findings_count = count_res.scalar()

            return ScanStatusResponse(
                id=scan.id,
                state=ScanState(scan.status),
                message=scan.message or "",
                endpoints_count=scan.endpoints_count or 0,
                findings_count=findings_count
            )

    async def get_results(self, scan_id: str) -> List[Vulnerability]:
        async with AsyncSessionLocal() as session:
             stmt = select(DBFinding).where(DBFinding.scan_id == scan_id)
             result = await session.execute(stmt)
             db_findings = result.scalars().all()
             
             from apscan.core.context import Severity, HttpMethod
             
             findings = []
             for dbf in db_findings:
                 findings.append(Vulnerability(
                     rule_id=dbf.rule_id,
                     name=dbf.name,
                     severity=Severity(dbf.severity),
                     description=dbf.description,
                     endpoint=dbf.endpoint,
                     method=HttpMethod(dbf.method),
                     evidence=dbf.evidence,
                     recommendation=dbf.recommendation,
                     reproduce_curl=dbf.reproduce_curl,
                     request_details=dbf.request_details,
                     response_details=dbf.response_details
                 ))
             return findings

    async def get_history(self) -> List[ScanStatusResponse]:
        async with AsyncSessionLocal() as session:
            # Fetch all scans ordered by created_at desc
            stmt = select(DBScan).order_by(desc(DBScan.created_at))
            result = await session.execute(stmt)
            scans = result.scalars().all()
            
            history = []
            for scan in scans:
                # Optimized count: We could do a group by query, but n+1 is fine for MVP history list (usually small)
                # Or just fetch count
                from sqlalchemy import func
                count_stmt = select(func.count()).select_from(DBFinding).where(DBFinding.scan_id == scan.id)
                count_res = await session.execute(count_stmt)
                findings_count = count_res.scalar()

                history.append(ScanStatusResponse(
                    id=scan.id,
                    state=ScanState(scan.status),
                    message=scan.message or "",
                    endpoints_count=scan.endpoints_count or 0,
                    findings_count=findings_count
                ))
            return history

    async def delete_scan(self, scan_id: str) -> bool:
        from sqlalchemy import delete
        
        async with AsyncSessionLocal() as session:
            # Delete findings first
            await session.execute(delete(DBFinding).where(DBFinding.scan_id == scan_id))
            # Delete scan
            result = await session.execute(delete(DBScan).where(DBScan.id == scan_id))
            await session.commit()
            return result.rowcount > 0

    async def generate_report(self, scan_id: str) -> Optional[str]:
        findings = await self.get_results(scan_id)
        
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(DBScan).where(DBScan.id == scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                return None
            
            # Extract target URL from config
            config = scan.input_config
            target_url = config.get('target_url') or "Unknown Target"
            
        from apscan.reporting.html_report import HTMLReporter
        reporter = HTMLReporter()
        return reporter.create_content(target_url, findings)

    async def generate_pdf_report(self, scan_id: str) -> Optional[bytes]:
        # Get HTML content first
        html_content = await self.generate_report(scan_id)
        if not html_content:
            return None
            
        from apscan.reporting.pdf_report import PDFReporter
        return PDFReporter.convert_html_to_pdf(html_content)
