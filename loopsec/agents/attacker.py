"""
Attacker Agent

Performs dynamic security testing against a deployed application:
- OWASP ZAP spider + active scan
- Nuclei template-based scanning
- LLM-driven creative attack generation
- Generates proof-of-concept exploits for each finding
"""

from __future__ import annotations

from rich.console import Console

from loopsec.agents.base import BaseAgent
from loopsec.core.models import Exploit, Finding, FindingSource, PipelineState, PipelineStatus, Severity
from loopsec.tools.nuclei import run_nuclei
from loopsec.tools.zap import run_zap_scan

console = Console()


class AttackerAgent(BaseAgent):
    name = "attacker"
    description = "Dynamic pentesting: ZAP, Nuclei, and LLM-driven attack generation"

    def run(self, state: PipelineState) -> PipelineState:
        state.status = PipelineStatus.ATTACKING
        target_url = state.target.app_url

        if not target_url:
            self.logger.warning("No target URL configured, skipping DAST")
            state.errors.append("Attacker: No app_url provided, skipping DAST phase")
            return state

        console.print(f"  [dim]Target: {target_url}[/dim]")

        # 1. Nuclei template scan (fast, low noise)
        console.print("  [dim]Running Nuclei...[/dim]")
        nuclei_findings = run_nuclei(target_url)
        console.print(f"  [dim]Nuclei: {len(nuclei_findings)} findings[/dim]")

        # 2. ZAP spider + active scan (deeper, slower)
        console.print("  [dim]Running ZAP scan...[/dim]")
        zap_findings = run_zap_scan(target_url)
        console.print(f"  [dim]ZAP: {len(zap_findings)} findings[/dim]")

        # 3. Merge and deduplicate
        dast_findings = self._deduplicate(nuclei_findings + zap_findings)

        # 4. LLM-driven creative attack suggestions based on SAST context
        if state.findings:  # We have SAST findings to guide attacks
            creative_findings = self._llm_attack_generation(state, target_url)
            dast_findings.extend(creative_findings)

        # 5. Generate proof-of-concept exploits
        for finding in dast_findings:
            state.add_finding(finding)
            self._emit({
                "type": "finding_added",
                "finding": {
                    "id": finding.id,
                    "severity": finding.severity.value,
                    "source": finding.source.value,
                    "title": finding.title,
                    "file_path": finding.file_path,
                    "line_start": finding.line_start,
                    "endpoint": finding.endpoint,
                    "tool": finding.tool,
                },
            })
            exploit = self._generate_exploit(finding)
            if exploit:
                state.add_exploit(exploit)
                self._emit({
                    "type": "exploit_added",
                    "exploit": {
                        "id": exploit.id,
                        "finding_id": exploit.finding_id,
                        "description": exploit.description,
                        "verified": exploit.verified,
                    },
                })

        console.print(
            f"  [bold]Total DAST findings: {len(dast_findings)}, "
            f"Exploits generated: {len(state.exploits)}[/bold]"
        )

        return state

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Deduplicate DAST findings by endpoint + vulnerability type."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.endpoint, f.cwe_id, f.title)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _llm_attack_generation(
        self, state: PipelineState, target_url: str
    ) -> list[Finding]:
        """
        Use LLM to suggest creative attacks based on SAST findings.
        E.g., if SAST found SQL injection in a handler, generate targeted
        DAST payloads for the corresponding endpoint.
        """
        sast_findings = state.get_sast_findings()
        if not sast_findings:
            return []

        # Build context from top SAST findings
        sast_context = ""
        for f in sast_findings[:10]:
            sast_context += (
                f"- {f.title} in {f.file_path}:{f.line_start} "
                f"(CWE: {f.cwe_id or 'N/A'})\n"
                f"  Code: {(f.code_snippet or 'N/A')[:100]}\n"
            )

        prompt = f"""You are an expert penetration tester. Based on the SAST findings below,
suggest 3-5 creative attack vectors to test against the running application at {target_url}.

SAST Findings:
{sast_context}

For each attack, provide:
1. The target endpoint (guess from code context — e.g., handler names, route patterns)
2. The attack type (SQLi, XSS, SSRF, Auth Bypass, IDOR, etc.)
3. A specific payload or test request
4. Why this attack is likely to work based on the code

Respond in JSON format:
{{
  "attacks": [
    {{
      "endpoint": "/api/users",
      "method": "POST",
      "attack_type": "SQL Injection",
      "payload": "' OR 1=1 --",
      "parameter": "username",
      "reasoning": "The code concatenates user input directly into SQL query"
    }}
  ]
}}"""

        try:
            result = self.llm.chat_json(prompt)
            attacks = result.get("attacks", [])
        except Exception as e:
            self.logger.warning(f"LLM attack generation failed: {e}")
            return []

        findings = []
        for atk in attacks[:5]:
            finding = Finding(
                source=FindingSource.DAST,
                severity=Severity.MEDIUM,  # Conservative — needs verification
                title=f"LLM-Suggested: {atk.get('attack_type', 'Unknown')}",
                description=(
                    f"AI-suggested attack vector: {atk.get('reasoning', 'N/A')}. "
                    f"Payload: {atk.get('payload', 'N/A')}"
                ),
                endpoint=atk.get("endpoint"),
                http_method=atk.get("method", "GET"),
                parameter=atk.get("parameter"),
                tool="llm-attacker",
                raw_output=atk,
            )
            findings.append(finding)

        self.logger.info(f"LLM suggested {len(findings)} creative attacks")
        return findings

    def _generate_exploit(self, finding: Finding) -> Exploit | None:
        """Generate a PoC exploit for a DAST finding."""
        raw = finding.raw_output or {}

        # For ZAP/Nuclei findings, the raw output often has the request
        request = raw.get("request") or raw.get("attack") or ""
        response = raw.get("response") or raw.get("evidence") or ""

        if not request and not finding.endpoint:
            return None

        # Build basic exploit from available data
        if request:
            exploit = Exploit(
                finding_id=finding.id,
                description=f"PoC for: {finding.title}",
                request=request[:2000],
                response_snippet=response[:1000] if response else None,
                steps=[
                    f"Send request to {finding.endpoint or 'target'}",
                    f"Observe vulnerability in response",
                ],
                verified=True,  # Tool-generated findings are pre-verified
            )
        else:
            # For LLM-suggested attacks, build a curl command
            payload = raw.get("payload", "test")
            endpoint = finding.endpoint or "/"
            method = finding.http_method or "GET"

            curl_cmd = f"curl -X {method} '{finding.endpoint}'"
            if finding.parameter:
                curl_cmd += f" -d '{finding.parameter}={payload}'"

            exploit = Exploit(
                finding_id=finding.id,
                description=f"Suggested PoC for: {finding.title}",
                request=curl_cmd,
                steps=[
                    f"Run the following command against the target",
                    curl_cmd,
                    f"Check for {finding.title} indicators in response",
                ],
                verified=False,  # Needs manual verification
            )

        return exploit
