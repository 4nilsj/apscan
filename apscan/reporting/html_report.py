from apscan.core.context import ScanContext
from apscan.reporting.base import Reporter
import os

class HTMLReporter(Reporter):
    def generate(self, context: ScanContext):
        content = self.create_content(context.target.url, context.findings)
        
        output_file = "scan_report.html"
        with open(output_file, 'w') as f:
            f.write(content)
        
        print(f"[*] HTML Report generated at {os.path.abspath(output_file)}")

    def create_content(self, target_url: str, findings: list) -> str:
        content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>APScan Security Report</title>
            <style>
                body {{ font-family: sans-serif; margin: 20px; }}
                h1 {{ color: #2c3e50; }}
                .summary {{ background: #ecf0f1; padding: 10px; border-radius: 5px; }}
                .finding {{ border: 1px solid #ddd; margin: 10px 0; padding: 10px; border-radius: 5px; }}
                .high {{ border-left: 5px solid #e74c3c; }}
                .medium {{ border-left: 5px solid #f39c12; }}
                .low {{ border-left: 5px solid #3498db; }}
            </style>
        </head>
        <body>
            <h1>APScan Security Report</h1>
            <div class="summary">
                <p><strong>Target:</strong> {target_url}</p>
                <p><strong>Total Findings:</strong> {len(findings)}</p>
            </div>
            <h2>Findings</h2>
        """
        
        if not findings:
            content += "<p>No vulnerabilities found.</p>"
            
        # Group by Rule
        from collections import defaultdict
        grouped = defaultdict(list)
        for f in findings:
            grouped[f.name].append(f)
            
        for rule_name, findings in grouped.items():
            first = findings[0]
            severity_class = first.severity.value.lower()
            
            content += f"""
            <div class="finding {severity_class}">
                <h3>[{first.severity.value}] {rule_name} ({len(findings)} occurrences)</h3>
                <p><strong>Description:</strong> {first.description}</p>
                <p><strong>Impact:</strong> {getattr(first, 'impact', 'N/A')}</p>
                <p><strong>Recommendation:</strong> {first.recommendation}</p>
                
                <details>
                    <summary>View Affected Endpoints & Evidence</summary>
                    <ul>
            """
            for f in findings:
                 content += f"""
                    <li>
                        <strong>{f.method.value} {f.endpoint}</strong>
                        <pre>{f.evidence}</pre>
                        {f'<div><strong>AI Insight:</strong><pre style="background:#f0faff; padding:10px; border:1px solid #cceeff;">{f.ai_analysis}</pre></div>' if getattr(f, 'ai_analysis', None) else ''}
                    </li>
                 """
            content += """
                    </ul>
                </details>
            </div>
            """
            
        content += """
        </body>
        </html>
        """
        return content
