from typing import Dict, List


class DependencyScanner:
    """Basic dependency risk analysis for known vulnerable packages."""

    def scan(self, code: str, requirements: str = "") -> List[Dict]:
        findings: List[Dict] = []
        known_risky = {
            "django": "Django versions before 4.2 may include security issues; ensure patch level is current.",
            "flask": "Review Flask version and dependency tree for security advisories.",
            "jinja2": "Jinja2 may be vulnerable to template injection if user-controlled templates are used.",
            "requests": "Ensure Requests is updated to a patched version and disable unsafe redirects.",
            "lodash": "Old lodash versions can expose prototype pollution and XSS paths.",
            "axios": "Review SSRF risk and certificate validation settings.",
        }

        text = (code + "\n" + requirements).lower()
        for pkg, message in known_risky.items():
            if pkg in text:
                findings.append({
                    "type": "DEPENDENCY_RISK",
                    "severity": "MEDIUM",
                    "dependency": pkg,
                    "description": message,
                    "confidence": 0.7,
                })
        return findings
