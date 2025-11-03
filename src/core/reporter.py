"""
Report generation for threat intelligence
"""
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
from .analyzer import AttackAnalyzer


class Reporter:
    """Generate threat intelligence reports"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.report_dir = Path(
            config.get('reporting', {}).get('report_dir', 'reports')
        )
        self.report_dir.mkdir(exist_ok=True)
        self.analyzer = AttackAnalyzer(
            config.get('logging', {}).get('log_dir', 'logs')
        )

    def generate_report(self, days: int = 1, formats: list = None):
        """Generate report in specified formats"""
        if formats is None:
            formats = self.config.get('reporting', {}).get('format', ['json'])

        # Perform analysis
        analysis = self.analyzer.analyze(days)

        # Generate timestamp for filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Generate each format
        for fmt in formats:
            if fmt == 'json':
                self._generate_json(analysis, timestamp)
            elif fmt == 'html':
                self._generate_html(analysis, timestamp)
            elif fmt == 'text':
                self._generate_text(analysis, timestamp)

    def _generate_json(self, analysis: Dict, timestamp: str):
        """Generate JSON report"""
        filename = self.report_dir / f"report_{timestamp}.json"

        with open(filename, 'w') as f:
            json.dump(analysis, f, indent=2)

        print(f"JSON report saved: {filename}")

    def _generate_text(self, analysis: Dict, timestamp: str):
        """Generate text report"""
        filename = self.report_dir / f"report_{timestamp}.txt"

        summary = self.analyzer.get_summary(analysis)

        with open(filename, 'w') as f:
            f.write(summary)

        print(f"Text report saved: {filename}")

    def _generate_html(self, analysis: Dict, timestamp: str):
        """Generate HTML report"""
        filename = self.report_dir / f"report_{timestamp}.html"

        html = self._build_html(analysis)

        with open(filename, 'w') as f:
            f.write(html)

        print(f"HTML report saved: {filename}")

    def _build_html(self, analysis: Dict) -> str:
        """Build HTML report content"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Honeypot Attack Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
        }}
        .metric {{
            background-color: #ecf0f1;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid #3498db;
        }}
        .metric-label {{
            font-weight: bold;
            color: #7f8c8d;
        }}
        .metric-value {{
            font-size: 24px;
            color: #2c3e50;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #3498db;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .warning {{
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 10px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Authentication Honeypot - Threat Intelligence Report</h1>
        <p><strong>Generated:</strong> {analysis.get('timestamp', 'N/A')}</p>
        <p><strong>Analysis Period:</strong> {analysis.get('analysis_period_days', 'N/A')} day(s)</p>

        <h2>Summary Metrics</h2>
        <div class="metric">
            <div class="metric-label">Total Attack Attempts</div>
            <div class="metric-value">{analysis.get('total_attacks', 0)}</div>
        </div>

        <div class="metric">
            <div class="metric-label">Unique Source IPs</div>
            <div class="metric-value">{analysis.get('by_source', {}).get('unique_sources', 0)}</div>
        </div>

        <h2>Attacks by Protocol</h2>
        <table>
            <tr>
                <th>Protocol</th>
                <th>Attack Count</th>
            </tr>
"""

        # Add protocol rows
        for protocol, count in analysis.get('by_protocol', {}).items():
            html += f"""            <tr>
                <td>{protocol}</td>
                <td>{count}</td>
            </tr>
"""

        html += """        </table>

        <h2>Top Source IPs</h2>
        <table>
            <tr>
                <th>IP Address</th>
                <th>Attack Count</th>
            </tr>
"""

        # Add top sources
        for ip, count in list(analysis.get('by_source', {}).get('top_sources', {}).items())[:10]:
            html += f"""            <tr>
                <td>{ip}</td>
                <td>{count}</td>
            </tr>
"""

        html += """        </table>

        <h2>Top Usernames</h2>
        <table>
            <tr>
                <th>Username</th>
                <th>Attempts</th>
            </tr>
"""

        # Add top usernames
        for item in analysis.get('top_usernames', [])[:10]:
            html += f"""            <tr>
                <td>{item.get('value', 'N/A')}</td>
                <td>{item.get('count', 0)}</td>
            </tr>
"""

        html += """        </table>
"""

        # Add repeat offenders if any
        offenders = analysis.get('repeat_offenders', [])
        if offenders:
            html += """
        <h2>Repeat Offenders</h2>
        <div class="warning">
            <strong>Warning:</strong> The following IPs have made 10 or more attack attempts.
        </div>
        <table>
            <tr>
                <th>IP Address</th>
                <th>Total Attempts</th>
            </tr>
"""
            for offender in offenders[:20]:
                html += f"""            <tr>
                <td>{offender.get('ip', 'N/A')}</td>
                <td>{offender.get('attempts', 0)}</td>
            </tr>
"""
            html += """        </table>
"""

        html += """    </div>
</body>
</html>
"""
        return html
