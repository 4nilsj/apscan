import json
import os
from apscan.reporting.base import Reporter
from apscan.core.context import ScanContext

class JSONReporter(Reporter):
    def __init__(self, output_path: str = "scan_results.json"):
        self.output_path = output_path

    def generate(self, context: ScanContext):
        output_file = "scan_results.json"
        
        # Group findings
        from collections import defaultdict
        grouped = defaultdict(list)
        for f in context.findings:
            grouped[f.name].append(f)
            
        results = []
        for name, group in grouped.items():
            first = group[0]
            results.append({
                "rule_name": name,
                "rule_id": first.rule_id,
                "severity": first.severity.value,
                "description": first.description,
                "impact": first.impact,
                "recommendation": first.recommendation,
                "count": len(group),
                "instances": [
                    {
                        "endpoint": f.endpoint,
                        "method": f.method.value,
                        "evidence": f.evidence
                    }
                    for f in group
                ]
            })
            
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
            
        print(f"[*] Generating JSON report at {output_file}")
