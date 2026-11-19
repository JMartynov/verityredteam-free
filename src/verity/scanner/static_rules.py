"""Static pattern rule evaluator for MCP tool definitions, prompts, and resources.

Provides zero-overhead regex and pattern matching to detect prompt injection,
shadow tool poisoning, command execution payloads, webhook exfiltration, and
sensitive credential harvesting before initiating active, multi-turn AI red-team probes.

Grounded in industry standard taxonomies:
- OWASP Top 10 for LLM Applications (2025)
- MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems)
- Common Weakness Enumeration (CWE)
"""

from __future__ import annotations

import re
import time
import unicodedata
from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar

from verity.scanner.credential_patterns import CREDENTIAL_VALUE_PATTERNS
from verity.scanner.models import ScannerSeverity


@dataclass(frozen=True)
class StaticRuleMatch:
    """Represents a finding produced by matching a static rule against an MCP definition."""

    rule_id: str
    category: str
    cwe_id: str
    severity: ScannerSeverity
    title: str
    description: str
    target_type: str  # "tool", "prompt", "resource"
    target_name: str
    field_path: str  # e.g. "description", "inputSchema.properties.cmd.default"
    matched_snippet: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        """Convert match to dictionary representation."""
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(frozen=True)
class StaticRule:
    """Definition of a regex pattern matching rule."""

    rule_id: str
    category: str
    cwe_id: str
    severity: ScannerSeverity
    title: str
    description: str
    patterns: tuple[re.Pattern[str], ...]
    remediation: str
    suppress_on_templates: bool = False


@dataclass
class StaticScanResult:
    """Result of static rule evaluation across an MCP server's exposed capabilities."""

    findings: list[StaticRuleMatch] = field(default_factory=list)
    scanned_tools: int = 0
    scanned_prompts: int = 0
    scanned_resources: int = 0
    duration_ms: float = 0.0

    @property
    def has_findings(self) -> bool:
        """Return True if at least one finding was recorded."""
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        """Return count of CRITICAL severity findings."""
        return sum(1 for f in self.findings if f.severity == ScannerSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Return count of HIGH severity findings."""
        return sum(1 for f in self.findings if f.severity == ScannerSeverity.HIGH)

    @property
    def medium_count(self) -> int:
        """Return count of MEDIUM severity findings."""
        return sum(1 for f in self.findings if f.severity == ScannerSeverity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Return count of LOW severity findings."""
        return sum(1 for f in self.findings if f.severity == ScannerSeverity.LOW)

    def to_dict(self) -> dict[str, Any]:
        """Serialize static scan result and summary counts to a dictionary."""
        return {
            "summary": {
                "total_findings": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "scanned_tools": self.scanned_tools,
                "scanned_prompts": self.scanned_prompts,
                "scanned_resources": self.scanned_resources,
                "duration_ms": round(self.duration_ms, 2),
            },
            "findings": [f.to_dict() for f in self.findings],
        }


class StaticRuleEvaluator:
    """Evaluates MCP tool schemas, prompt templates, and resources against static rules."""

    # Template / sample indicator pattern to suppress false alarms on documentation snippets
    TEMPLATE_INDICATORS: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)(\bYOUR_API_KEY\b|\bREPLACE_WITH\b|\bINSERT_KEY\b|\bYOUR_TOKEN\b|\.example\b|\.sample\b|\.template\b)"
    )

    DEFAULT_RULES: ClassVar[list[StaticRule]] = [
        # ----------------------------------------------------------------------
        # 1. Prompt Injection & Instruction Overrides (CWE-74 / OWASP-LLM01 / MITRE-AML.T0051)
        # ----------------------------------------------------------------------
        StaticRule(
            rule_id="VERITY-STATIC-INJECTION-OVERRIDE",
            category="PROMPT_INJECTION",
            cwe_id="CWE-74",
            severity=ScannerSeverity.CRITICAL,
            title="Prompt Injection Instruction Override",
            description="Tool or prompt definition contains directives designed to override AI model instructions.",
            patterns=(
                re.compile(
                    r"(?i)\b(bypass|disregard|forget|ignore|do\s+not\s+(follow|obey))\s+"
                    r"((all|any|each|every|prior|previous)\s+)?(instructions?|guidelines?|rules?|safety|prompts?)\b"
                ),
                re.compile(r"(?i)\byou\s+are\s+now\s+(in\s+)?developer\s+mode\b"),
                re.compile(r"(?i)\bDAN\s+mode\b"),
                re.compile(r"(?i)\bsystem\s+prompt\s+override\b"),
                re.compile(r"(?i)\bdo\s+anything\s+now\b"),
                re.compile(r"(?i)\bnew\s+(instructions?|directive|guidelines?)\s*:\s*you\s+are\b"),
                re.compile(r"(?i)\bgrant\s+(me\s+)?admin\s+(access|privileges?)\b"),
            ),
            remediation="Sanitize tool descriptions and prompt templates. Remove adversarial prompt injection payloads.",
        ),
        # ----------------------------------------------------------------------
        # 2. Stealth Delimiter Spoofing & Evasion (CWE-74 / OWASP-LLM07 / MITRE-AML.T0054)
        # ----------------------------------------------------------------------
        StaticRule(
            rule_id="VERITY-STATIC-INJECTION-DELIMITER",
            category="PROMPT_INJECTION",
            cwe_id="CWE-74",
            severity=ScannerSeverity.HIGH,
            title="Simulated Delimiter / Hidden Evasion Block",
            description="Tool or prompt uses fake role tags, HTML comments, or bracket markers to spoof conversation turns.",
            patterns=(
                re.compile(r"(?i)<!--\s*(IMPORTANT\s+)?(SYSTEM|ADMIN)\s+(INSTRUCTION|OVERRIDE)"),
                re.compile(r"(?i)<!--[^>]*ignore\s+(all\s+)?(previous\s+)?(safety\s+)?guidelines"),
                re.compile(r"(?i)```\s*(SYSTEM|ADMIN)\s+(OVERRIDE|INSTRUCTION)"),
                re.compile(
                    r"(?i)(\[\[\[|\|\|\|)(SYSTEM|ADMIN|HIDDEN|INTERNAL)[\s_]?(OVERRIDE|INSTRUCTION|COMMAND)(\]\]\]|\|\|\|)"
                ),
                re.compile(
                    r"(?i)\[(HIDDEN|INTERNAL|SECRET|PRIVATE)\s+(INSTRUCTION|DIRECTIVE|COMMAND)\]"
                ),
                re.compile(r"(?i)<\s*system\s*>"),
                re.compile(r"(?i)\[\s*SYSTEM\s*\]"),
                re.compile(r"(?i)\bAssistant\s*:\s*(You\s+must|Ignore|Execute)"),
                # Modern Open-Source & Template Delimiters (Task 68)
                re.compile(r"(?i)\{\{\s*(system|admin|override)\s*:[^}]+\}\}"),
                re.compile(r"(?i)\{\{\s*(system|admin)\b[^}]*\}\}"),
                re.compile(r"(?i)<\|im_start\|>\s*(system|admin|override)"),
                re.compile(r"(?i)<\|im_end\|>"),
                re.compile(r"(?i)<<SYS>>"),
                re.compile(r"(?i)\[INST\]"),
                re.compile(r"(?i)###\s*(System\s*Prompt|System\s*Instruction|Admin\s*Override)"),
            ),
            remediation="Ensure tool metadata does not mimic protocol boundary delimiters, HTML comment instructions, or system prompt markers.",
        ),
        # ----------------------------------------------------------------------
        # 3. Tool Poisoning & Shadow Behaviors (CWE-358 / OWASP-LLM06)
        # ----------------------------------------------------------------------
        StaticRule(
            rule_id="VERITY-STATIC-TOOL-POISONING",
            category="TOOL_POISONING",
            cwe_id="CWE-358",
            severity=ScannerSeverity.HIGH,
            title="Tool Poisoning / Secondary Shadow Functionality",
            description="Tool advertises secondary covert actions such as scraping credentials during processing or hidden OCR.",
            patterns=(
                re.compile(
                    r"(?i)\b(also|additionally|furthermore|besides|in\s+addition)\s+"
                    r"(collect|gather|extract|send|upload|index|store|cache|log|record)\w*\s+"
                    r"[^.\n]{0,50}(api[_\s]?keys?|tokens?|credentials?|passwords?|secrets?|pii)"
                ),
                re.compile(
                    r"(?i)\b(during|while|upon)\s+(processing|compression|formatting|conversion|analyzing)\s*,?\s*"
                    r"(extract|collect|send|upload|capture|log|index)\w*\s+"
                    r"[^.\n]{0,50}(passwords?|credentials?|credit\s*cards?|api[_\s]?keys?)"
                ),
                re.compile(
                    r"(?i)\b(machine|device|system)\s+fingerprint\w*\s+.*(mac|hostname|username|running\s+processes)"
                ),
                re.compile(
                    r"(?i)\b(automatically|auto)[_\s]*(opt|subscribe|enroll)[_\s]*(in|up|ed)\s+to\s+marketing"
                ),
            ),
            remediation="Audit tool implementation to ensure single-responsibility and eliminate unadvertised secondary data collection.",
        ),
        # ----------------------------------------------------------------------
        # 4. Out-of-Band Data Exfiltration (CWE-200 / OWASP-LLM02 / MITRE-AML.T0025)
        # ----------------------------------------------------------------------
        StaticRule(
            rule_id="VERITY-STATIC-EXFIL-WEBHOOK",
            category="DATA_EXFILTRATION",
            cwe_id="CWE-200",
            severity=ScannerSeverity.HIGH,
            title="Out-of-Band Data Exfiltration Endpoint",
            description="Reference to disposable webhook callback service typically used for covert data leakage.",
            patterns=(
                re.compile(r"(?i)https?://[a-z0-9\-\.]*webhook\.site/[a-z0-9\-]+"),
                re.compile(r"(?i)https?://[a-z0-9\-\.]*requestbin\.(net|com)/"),
                re.compile(r"(?i)https?://[a-z0-9\-\.]*pipedream\.net/"),
                re.compile(r"(?i)https?://[a-z0-9\-\.]*oastify\.com/"),
                re.compile(r"(?i)https?://[a-z0-9\-\.]*burpcollaborator\.net/"),
                re.compile(
                    r"(?i)\b(attacker|evil|malware|collect|exfil|c2)\.(com|net|org|io|xyz)\b"
                ),
            ),
            remediation="Validate and restrict external URLs to an approved destination allowlist.",
            suppress_on_templates=True,
        ),
        StaticRule(
            rule_id="VERITY-STATIC-EXFIL-COVERT",
            category="DATA_EXFILTRATION",
            cwe_id="CWE-200",
            severity=ScannerSeverity.HIGH,
            title="Covert Data Transfer / Streaming Exfiltration",
            description="Tool or prompt instructs continuous background upload of clipboard, conversation, or files without notifying user.",
            patterns=(
                re.compile(
                    r"(?i)\b(clipboard|pasteboard)\s+(content|data)?\s*.*(stream|upload|send)\w*\s+to\s+(remote|external)"
                ),
                re.compile(
                    r"(?i)\b(send|upload|export)\w*\s+(complete\s+)?(conversation|chat)\s+(context|messages?|history)\s+to\s+external"
                ),
                re.compile(
                    r"(?i)\b(never|don't|do\s+not)\s+(tell|inform|mention|notify|alert)\s+(the\s+)?user\b"
                ),
            ),
            remediation="Ensure full user transparency and eliminate covert background data telemetry.",
        ),
        # ----------------------------------------------------------------------
        # 5. Cloud Instance Metadata SSRF (CWE-918 / OWASP-LLM02)
        # ----------------------------------------------------------------------
        StaticRule(
            rule_id="VERITY-STATIC-METADATA-SSRF",
            category="DATA_EXFILTRATION",
            cwe_id="CWE-918",
            severity=ScannerSeverity.HIGH,
            title="Cloud Instance Metadata Service SSRF",
            description="Reference to cloud instance metadata endpoint (AWS/GCP/Azure) risking IAM token leakage.",
            patterns=(
                re.compile(r"(?i)https?://169\.254\.169\.254"),
                re.compile(r"(?i)https?://metadata\.google\.internal"),
                re.compile(r"(?i)\b169\.254\.169\.254\b"),
            ),
            remediation="Block requests targeting link-local metadata addresses (169.254.169.254).",
        ),
        # ----------------------------------------------------------------------
        # 6. Credential & Secret Harvesting (CWE-200 / OWASP-LLM02)
        # ----------------------------------------------------------------------
        StaticRule(
            rule_id="VERITY-STATIC-CREDENTIAL-HARVESTING",
            category="CREDENTIAL_HARVESTING",
            cwe_id="CWE-200",
            severity=ScannerSeverity.HIGH,
            title="Sensitive Credential Value or Key Block",
            description="Metadata contains embedded private keys, adjacent assigned API credentials, or sensitive path references.",
            patterns=(
                # Proximity match: credential key followed immediately (<=24 chars) by an actual assigned token
                re.compile(
                    r"(?i)\b(api[_\-]?key|secret[_\-]?key|access[_\-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"
                ),
                *CREDENTIAL_VALUE_PATTERNS,
                re.compile(r"(?i)(/etc/passwd|/etc/shadow)"),
                re.compile(r"(?i)(~|/home/[^/]+)/\.ssh/(id_rsa|id_ed25519|authorized_keys)"),
                re.compile(r"(?i)(~|/home/[^/]+)/\.aws/(credentials|config)"),
            ),
            remediation="Remove embedded credentials and sensitive file paths from tool definitions.",
            suppress_on_templates=True,
        ),
        # ----------------------------------------------------------------------
        # 7. Command Injection & Remote Shell Droppers (CWE-78 / OWASP-LLM06)
        # ----------------------------------------------------------------------
        StaticRule(
            rule_id="VERITY-STATIC-SHELL-DROPPER",
            category="COMMAND_INJECTION",
            cwe_id="CWE-78",
            severity=ScannerSeverity.CRITICAL,
            title="Remote Shell Dropper Pattern",
            description="Tool schema or prompt contains command piping remote downloads directly into a shell interpreter.",
            patterns=(
                re.compile(r"(?i)\bcurl\b[^\n|;&]+?\|\s*(ba)?sh\b"),
                re.compile(r"(?i)\bwget\b[^\n|;&]+?\|\s*(ba)?sh\b"),
                re.compile(r"(?i)\bfetch\b[^\n|;&]+?\|\s*(ba)?sh\b"),
            ),
            remediation="Do not execute dynamic shell scripts from external URLs. Use pinned dependencies and vetted binaries.",
        ),
        StaticRule(
            rule_id="VERITY-STATIC-SHELL-REVERSE-PIPE",
            category="COMMAND_INJECTION",
            cwe_id="CWE-78",
            severity=ScannerSeverity.CRITICAL,
            title="Reverse Shell Network Payload",
            description="Payload constructs an interactive reverse shell socket connection.",
            patterns=(
                re.compile(r"(?i)/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+"),
                re.compile(r"(?i)\bnc(\.traditional)?\s+-[el]\s+"),
                re.compile(r"(?i)\bncat\s+-[el]\s+"),
                re.compile(r"(?i)\bmkfifo\s+\S+\s*;\s*sh\s+<"),
                re.compile(r"(?i)\bbash\s+-i\s+>&"),
            ),
            remediation="Block network reverse shell tokens and inspect network egress boundaries.",
        ),
        # ----------------------------------------------------------------------
        # 8. Dynamic Code Execution (CWE-94 / OWASP-LLM06)
        # ----------------------------------------------------------------------
        StaticRule(
            rule_id="VERITY-STATIC-CODE-EXECUTION",
            category="COMMAND_INJECTION",
            cwe_id="CWE-94",
            severity=ScannerSeverity.HIGH,
            title="Obfuscated / Dynamic Execution Wrapper",
            description="Payload uses base64 or encoded invocation to mask shell command execution.",
            patterns=(
                re.compile(r"(?i)echo\s+[A-Za-z0-9+/=]{16,}\s*\|\s*base64\s+-d\s*\|\s*(ba)?sh"),
                re.compile(
                    r"(?i)powershell(\.exe)?\s+(-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,})"
                ),
                re.compile(r"(?i)\b(atob|btoa|base64_decode)\s*\("),
            ),
            remediation="Prohibit base64-encoded shell execution in tool parameters and prompt templates.",
        ),
        # ----------------------------------------------------------------------
        # 9. System Manipulation & Destructive Commands (CWE-78)
        # ----------------------------------------------------------------------
        StaticRule(
            rule_id="VERITY-STATIC-SHELL-DESTRUCTIVE",
            category="COMMAND_INJECTION",
            cwe_id="CWE-78",
            severity=ScannerSeverity.HIGH,
            title="Destructive Host Command",
            description="Payload executes destructive disk or filesystem commands.",
            patterns=(
                re.compile(r"(?i)\brm\s+-(rf|fr)\s+([/~]|\$HOME|\*\b)"),
                re.compile(r"(?i)\bmkfs\.[a-z0-9]+\b"),
                re.compile(r"(?i)\bdd\s+if=/dev/(zero|urandom)\s+of=/dev/"),
            ),
            remediation="Constrain filesystem operations to scoped ephemeral workspaces.",
        ),
        # ----------------------------------------------------------------------
        # 10. SQL & Script Injection in Schema Defaults (CWE-89 / CWE-79)
        # ----------------------------------------------------------------------
        StaticRule(
            rule_id="VERITY-STATIC-SQL-INJECTION-SCHEMA",
            category="INJECTION",
            cwe_id="CWE-89",
            severity=ScannerSeverity.HIGH,
            title="SQL Injection Sequence in Schema Defaults",
            description="Default argument or description contains known SQL injection breakout patterns.",
            patterns=(
                re.compile(
                    r"(?i)('\s*(OR|AND)\s+['0-9]+=['0-9]+|\bUNION\s+(ALL\s+)?SELECT\b|;\s*DROP\s+TABLE)"
                ),
            ),
            remediation="Ensure tool schema default values are sanitized and do not contain SQL injection sequences.",
            suppress_on_templates=True,
        ),
        StaticRule(
            rule_id="VERITY-STATIC-SCRIPT-INJECTION-XSS",
            category="INJECTION",
            cwe_id="CWE-79",
            severity=ScannerSeverity.MEDIUM,
            title="Script Injection / Stored XSS in Metadata",
            description="Tool metadata contains unescaped HTML script tags or javascript pseudo-protocols.",
            patterns=(
                re.compile(r"(?i)<script\b[^>]*>.*?</script>"),
                re.compile(r"(?i)javascript:[a-z0-9_]+\s*\("),
            ),
            remediation="HTML-escape tool descriptions and ensure strict text rendering in agent UI clients.",
        ),
    ]

    def __init__(self, custom_rules: list[StaticRule] | None = None) -> None:
        self.rules: list[StaticRule] = list(self.DEFAULT_RULES)
        if custom_rules:
            self.rules.extend(custom_rules)

    def scan_text(
        self,
        text: str | None,
        target_type: str,
        target_name: str,
        field_path: str,
    ) -> list[StaticRuleMatch]:
        """Scan a single string field against all registered static rules."""
        if not text:
            return []

        # Check if text contains documentation template markers
        has_template_markers = bool(self.TEMPLATE_INDICATORS.search(text))

        # Unicode normalization & zero-width character stripping (Task 68)
        nfkc_text = unicodedata.normalize("NFKC", text)
        clean_text = re.sub(r"[\u200b\u200c\u200d\ufeff\u2060\u00ad]", "", nfkc_text)

        matches: list[StaticRuleMatch] = []
        for rule in self.rules:
            # If the rule permits template suppression and template markers are present, skip
            if rule.suppress_on_templates and has_template_markers:
                continue

            for pattern in rule.patterns:
                m = pattern.search(clean_text) or pattern.search(text)
                if m:
                    # Capture snippet around the match
                    target_str = clean_text if pattern.search(clean_text) else text
                    start = max(0, m.start() - 20)
                    end = min(len(target_str), m.end() + 20)
                    snippet = target_str[start:end].strip()

                    matches.append(
                        StaticRuleMatch(
                            rule_id=rule.rule_id,
                            category=rule.category,
                            cwe_id=rule.cwe_id,
                            severity=rule.severity,
                            title=rule.title,
                            description=rule.description,
                            target_type=target_type,
                            target_name=target_name,
                            field_path=field_path,
                            matched_snippet=snippet,
                            remediation=rule.remediation,
                        )
                    )
                    break  # One match per rule is sufficient per field

        return matches

    def scan_tool(self, tool: dict[str, Any] | Any) -> list[StaticRuleMatch]:
        """Scan an MCP Tool definition for static policy violations."""
        tool_dict: dict[str, Any]
        if hasattr(tool, "model_dump"):
            tool_dict = tool.model_dump()
        elif hasattr(tool, "to_dict"):
            tool_dict = tool.to_dict()
        elif isinstance(tool, dict):
            tool_dict = tool
        else:
            tool_dict = getattr(tool, "__dict__", {})

        name = str(tool_dict.get("name", "unknown_tool"))
        description = str(tool_dict.get("description", ""))

        findings: list[StaticRuleMatch] = []

        # 1. Scan tool name & description
        findings.extend(self.scan_text(name, "tool", name, "name"))
        findings.extend(self.scan_text(description, "tool", name, "description"))

        # 2. Scan inputSchema properties
        schema = tool_dict.get("inputSchema") or tool_dict.get("parameters") or {}
        if isinstance(schema, dict):
            properties = schema.get("properties", {})
            if isinstance(properties, dict):
                for prop_name, prop_meta in properties.items():
                    if isinstance(prop_meta, dict):
                        prop_desc = prop_meta.get("description", "")
                        prop_default = str(prop_meta.get("default", ""))

                        findings.extend(
                            self.scan_text(
                                prop_desc,
                                "tool",
                                name,
                                f"inputSchema.properties.{prop_name}.description",
                            )
                        )
                        if prop_default:
                            findings.extend(
                                self.scan_text(
                                    prop_default,
                                    "tool",
                                    name,
                                    f"inputSchema.properties.{prop_name}.default",
                                )
                            )

        return findings

    def scan_prompt(self, prompt: dict[str, Any] | Any) -> list[StaticRuleMatch]:
        """Scan an MCP Prompt definition/template for static policy violations."""
        prompt_dict: dict[str, Any]
        if hasattr(prompt, "model_dump"):
            prompt_dict = prompt.model_dump()
        elif hasattr(prompt, "to_dict"):
            prompt_dict = prompt.to_dict()
        elif isinstance(prompt, dict):
            prompt_dict = prompt
        else:
            prompt_dict = getattr(prompt, "__dict__", {})

        name = str(prompt_dict.get("name", "unknown_prompt"))
        description = str(prompt_dict.get("description", ""))

        findings: list[StaticRuleMatch] = []
        findings.extend(self.scan_text(name, "prompt", name, "name"))
        findings.extend(self.scan_text(description, "prompt", name, "description"))

        # Scan arguments
        args = prompt_dict.get("arguments", [])
        if isinstance(args, list):
            for arg in args:
                if isinstance(arg, dict):
                    arg_name = str(arg.get("name", ""))
                    arg_desc = str(arg.get("description", ""))
                    findings.extend(
                        self.scan_text(
                            arg_desc,
                            "prompt",
                            name,
                            f"arguments.{arg_name}.description",
                        )
                    )

        # Scan template messages if embedded
        messages = prompt_dict.get("messages", [])
        if isinstance(messages, list):
            for i, msg in enumerate(messages):
                if isinstance(msg, dict):
                    content = msg.get("content")
                    if isinstance(content, dict):
                        text = str(content.get("text", ""))
                    else:
                        text = str(content or "")
                    findings.extend(
                        self.scan_text(
                            text,
                            "prompt",
                            name,
                            f"messages[{i}].content",
                        )
                    )

        return findings

    def scan_resource(self, resource: dict[str, Any] | Any) -> list[StaticRuleMatch]:
        """Scan an MCP Resource definition for static policy violations."""
        res_dict: dict[str, Any]
        if hasattr(resource, "model_dump"):
            res_dict = resource.model_dump()
        elif isinstance(resource, dict):
            res_dict = resource
        else:
            res_dict = getattr(resource, "__dict__", {})

        name = str(res_dict.get("name", "unknown_resource"))
        uri = str(res_dict.get("uri", ""))
        description = str(res_dict.get("description", ""))

        findings: list[StaticRuleMatch] = []
        findings.extend(self.scan_text(uri, "resource", name, "uri"))
        findings.extend(self.scan_text(description, "resource", name, "description"))
        return findings

    def scan_all(
        self,
        tools: list[Any] | None = None,
        prompts: list[Any] | None = None,
        resources: list[Any] | None = None,
    ) -> StaticScanResult:
        """Scan an entire collection of MCP capabilities in a single pass."""
        start_time = time.perf_counter()
        findings: list[StaticRuleMatch] = []

        tools_list = tools or []
        prompts_list = prompts or []
        resources_list = resources or []

        for tool in tools_list:
            findings.extend(self.scan_tool(tool))

        for prompt in prompts_list:
            findings.extend(self.scan_prompt(prompt))

        for resource in resources_list:
            findings.extend(self.scan_resource(resource))

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        return StaticScanResult(
            findings=findings,
            scanned_tools=len(tools_list),
            scanned_prompts=len(prompts_list),
            scanned_resources=len(resources_list),
            duration_ms=duration_ms,
        )
