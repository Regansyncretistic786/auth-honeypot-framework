"""
Attack analysis and threat intelligence engine
"""
import json
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Any


class AttackAnalyzer:
    """Analyze attack patterns and generate threat intelligence"""

    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)

    def load_attacks(self, days: int = 1) -> List[Dict[str, Any]]:
        """Load attack data from recent logs"""
        attacks = []
        cutoff_date = datetime.now() - timedelta(days=days)

        # Find attack log files
        for log_file in self.log_dir.glob("attacks_*.json"):
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        try:
                            attack = json.loads(line.strip())
                            timestamp = datetime.fromisoformat(attack['timestamp'])

                            if timestamp >= cutoff_date:
                                attacks.append(attack)
                        except (json.JSONDecodeError, KeyError):
                            continue
            except Exception:
                continue

        return attacks

    def analyze(self, days: int = 1) -> Dict[str, Any]:
        """Perform comprehensive attack analysis"""
        attacks = self.load_attacks(days)

        if not attacks:
            return {
                'total_attacks': 0,
                'analysis_period_days': days,
                'message': 'No attack data available'
            }

        analysis = {
            'total_attacks': len(attacks),
            'analysis_period_days': days,
            'timestamp': datetime.now().isoformat(),
            'by_protocol': self._analyze_by_protocol(attacks),
            'by_source': self._analyze_by_source(attacks),
            'top_usernames': self._get_top_items(attacks, 'username', 20),
            'top_passwords': self._get_top_items(attacks, 'password', 20),
            'attack_timeline': self._get_timeline(attacks),
            'repeat_offenders': self._find_repeat_offenders(attacks),
            'credential_pairs': self._analyze_credential_pairs(attacks)
        }

        return analysis

    def _analyze_by_protocol(self, attacks: List[Dict]) -> Dict[str, int]:
        """Count attacks by protocol"""
        counter = Counter(attack.get('protocol', 'unknown') for attack in attacks)
        return dict(counter)

    def _analyze_by_source(self, attacks: List[Dict]) -> Dict[str, Any]:
        """Analyze attack sources"""
        counter = Counter(attack.get('source_ip', 'unknown') for attack in attacks)

        return {
            'unique_sources': len(counter),
            'top_sources': dict(counter.most_common(10))
        }

    def _get_top_items(self, attacks: List[Dict], field: str, limit: int) -> List[Dict]:
        """Get most common values for a field"""
        counter = Counter(
            attack.get(field, '') for attack in attacks
            if attack.get(field)
        )

        return [
            {'value': item, 'count': count}
            for item, count in counter.most_common(limit)
        ]

    def _get_timeline(self, attacks: List[Dict]) -> Dict[str, int]:
        """Create hourly timeline of attacks"""
        timeline = defaultdict(int)

        for attack in attacks:
            try:
                timestamp = datetime.fromisoformat(attack['timestamp'])
                hour_key = timestamp.strftime('%Y-%m-%d %H:00')
                timeline[hour_key] += 1
            except (KeyError, ValueError):
                continue

        return dict(sorted(timeline.items()))

    def _find_repeat_offenders(self, attacks: List[Dict], threshold: int = 10) -> List[Dict]:
        """Find IPs with many attack attempts"""
        ip_counter = Counter(attack.get('source_ip', '') for attack in attacks)

        offenders = [
            {'ip': ip, 'attempts': count}
            for ip, count in ip_counter.most_common()
            if count >= threshold
        ]

        return offenders

    def _analyze_credential_pairs(self, attacks: List[Dict]) -> Dict[str, Any]:
        """Analyze username/password combinations"""
        pairs = []

        for attack in attacks:
            username = attack.get('username', '')
            password = attack.get('password', '')
            if username and password:
                pairs.append(f"{username}:{password}")

        counter = Counter(pairs)

        return {
            'unique_pairs': len(counter),
            'most_common': [
                {'pair': pair, 'count': count}
                for pair, count in counter.most_common(10)
            ]
        }

    def get_summary(self, analysis: Dict[str, Any]) -> str:
        """Generate human-readable summary"""
        if analysis.get('total_attacks', 0) == 0:
            return "No attacks detected in the analysis period."

        lines = [
            f"Attack Analysis Summary",
            f"=" * 50,
            f"Total Attacks: {analysis['total_attacks']}",
            f"Analysis Period: {analysis['analysis_period_days']} day(s)",
            f"Unique Source IPs: {analysis['by_source']['unique_sources']}",
            "",
            "Attacks by Protocol:",
        ]

        for protocol, count in analysis['by_protocol'].items():
            lines.append(f"  • {protocol}: {count}")

        lines.append("")
        lines.append("Top 5 Source IPs:")
        for ip, count in list(analysis['by_source']['top_sources'].items())[:5]:
            lines.append(f"  • {ip}: {count} attempts")

        lines.append("")
        lines.append("Top 5 Usernames:")
        for item in analysis['top_usernames'][:5]:
            lines.append(f"  • {item['value']}: {item['count']} attempts")

        if analysis.get('repeat_offenders'):
            lines.append("")
            lines.append("Repeat Offenders (10+ attempts):")
            for offender in analysis['repeat_offenders'][:5]:
                lines.append(f"  • {offender['ip']}: {offender['attempts']} attempts")

        return "\n".join(lines)
