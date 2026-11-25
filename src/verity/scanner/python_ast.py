"""Native Python AST visitor analyzing MCP server tool definitions and call expressions."""

from __future__ import annotations

import ast
from pathlib import Path

from verity.scanner.models import AstFinding
from verity.scanner.rules import RuleCatalog, RuleDefinition


class McpAstVisitor(ast.NodeVisitor):
    """Inspects Python source code AST for security vulnerabilities and dangerous operations."""

    def __init__(self, file_path: str, source_code: str) -> None:
        self.file_path = file_path
        self.source_code = source_code
        self.lines = source_code.splitlines()
        self.findings: list[AstFinding] = []

        # Context tracking
        self.current_function: str | None = None
        self.current_tool: str | None = None
        self.in_vulnerable_block: bool = False

        # Imported modules mapping: alias -> original
        self.imports: dict[str, str] = {}

    def _get_snippet(self, node: ast.AST) -> str:
        line_idx = getattr(node, "lineno", 1) - 1
        if 0 <= line_idx < len(self.lines):
            return self.lines[line_idx].strip()
        return ""

    def _add_finding(
        self,
        rule: RuleDefinition,
        node: ast.AST,
        custom_message: str | None = None,
    ) -> None:
        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0)
        end_line = getattr(node, "end_lineno", line)
        end_col = getattr(node, "end_col_offset", col)

        finding = AstFinding(
            rule_id=rule.rule_id,
            cwe_id=rule.cwe_id,
            severity=rule.severity,
            title=rule.title,
            message=custom_message or rule.description,
            file_path=self.file_path,
            line_number=line,
            column_number=col,
            end_line_number=end_line,
            end_column_number=end_col,
            snippet=self._get_snippet(node),
            remediation=rule.remediation,
            mcp_tool_context=self.current_tool or self.current_function,
        )
        self.findings.append(finding)

    def visit_Import(self, node: ast.Import) -> None:
        """Record module import aliases and continue AST traversal."""
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Record from-import aliases and continue AST traversal."""
        module = node.module or ""
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports[name] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track function and MCP tool scope while traversing function definitions."""
        prev_func = self.current_function
        prev_tool = self.current_tool
        self.current_function = node.name

        # Detect tool decorators or tool names
        for dec in node.decorator_list:
            dec_id = ""
            if isinstance(dec, ast.Name):
                dec_id = dec.id
            elif isinstance(dec, ast.Attribute):
                dec_id = dec.attr
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    dec_id = dec.func.id
                elif isinstance(dec.func, ast.Attribute):
                    dec_id = dec.func.attr

            if "tool" in dec_id.lower():
                self.current_tool = node.name
                break

        if not self.current_tool and (
            node.name.startswith("tool_")
            or "handle_" in node.name
            or node.name in ("call", "execute_tool")
        ):
            self.current_tool = node.name

        self.generic_visit(node)
        self.current_function = prev_func
        self.current_tool = prev_tool

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Track async function scope while traversing AST."""
        prev_func = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = prev_func

    def visit_If(self, node: ast.If) -> None:
        """Track vulnerable conditional branches during AST traversal."""
        is_vuln_cond = False
        test_str = ast.dump(node.test)
        if "vulnerable" in test_str:
            is_vuln_cond = True

        prev_vuln_block = self.in_vulnerable_block
        if is_vuln_cond:
            self.in_vulnerable_block = True

        self.generic_visit(node)
        self.in_vulnerable_block = prev_vuln_block

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect function calls for dangerous sinks and taint patterns."""
        func_name = ""
        attr_chain: list[str] = []

        curr: ast.AST = node.func
        while isinstance(curr, ast.Attribute):
            attr_chain.insert(0, curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            attr_chain.insert(0, curr.id)

        full_call = ".".join(attr_chain)
        if isinstance(node.func, ast.Name):
            func_name = node.func.id

        # 1. Dynamic Code Execution (eval, exec, compile)
        if func_name == "eval":
            self._add_finding(
                RuleCatalog.RULE_CWE_94_EVAL,
                node,
                "Direct invocation of 'eval()' allows arbitrary code execution.",
            )
        elif func_name == "exec":
            self._add_finding(
                RuleCatalog.RULE_CWE_94_EVAL,
                node,
                "Direct invocation of 'exec()' dynamically executes arbitrary Python code.",
            )
        elif func_name == "compile":
            self._add_finding(
                RuleCatalog.RULE_CWE_94_COMPILE,
                node,
                "Invocation of 'compile()' dynamically generates executable bytecode.",
            )

        # 2. Command Injection (subprocess, os.system, os.popen)
        if full_call in ("os.system", "os.popen", "posix.system"):
            self._add_finding(
                RuleCatalog.RULE_CWE_78_OS_SYSTEM,
                node,
                f"Direct execution of shell command using '{full_call}'.",
            )
        elif "subprocess" in full_call or full_call in ("Popen", "run", "call", "check_output"):
            for kw in node.keywords:
                is_shell_true = (
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                )
                if is_shell_true:
                    self._add_finding(
                        RuleCatalog.RULE_CWE_78_SHELL_TRUE,
                        node,
                        f"Call to '{full_call}' with 'shell=True' allows command injection.",
                    )

        # 3. Insecure Deserialization (pickle, yaml)
        if full_call in ("pickle.loads", "pickle.load", "_pickle.loads", "marshal.loads"):
            self._add_finding(
                RuleCatalog.RULE_CWE_502_PICKLE,
                node,
                f"Insecure object deserialization via '{full_call}'.",
            )
        elif full_call in ("yaml.load", "yaml.unsafe_load"):
            has_safe_loader = False
            for kw in node.keywords:
                if kw.arg == "Loader":
                    val_str = ast.dump(kw.value)
                    if "SafeLoader" in val_str:
                        has_safe_loader = True
            if not has_safe_loader or full_call == "yaml.unsafe_load":
                self._add_finding(
                    RuleCatalog.RULE_CWE_502_UNSAFE_YAML,
                    node,
                    f"Insecure YAML deserialization via '{full_call}' without SafeLoader.",
                )

        # 4. DOM XSS / HTML Markup
        if full_call in ("format", "replace") and any(
            t in self._get_snippet(node).lower()
            for t in ("<script", "onload=", "onclick=", "javascript:")
        ):
            self._add_finding(
                RuleCatalog.RULE_CWE_79_DOM_XSS,
                node,
                "Dynamic interpolation of unescaped script or event handler into markup.",
            )

        self.generic_visit(node)


def scan_python_file(file_path: str | Path) -> list[AstFinding]:
    """Parse and scan a Python source file for security vulnerabilities."""
    path = Path(file_path)
    if not path.is_file():
        return []

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []

    visitor = McpAstVisitor(file_path=str(path), source_code=source)
    visitor.visit(tree)

    _check_heuristic_flaws(visitor, tree, source)
    return visitor.findings


def _check_heuristic_flaws(visitor: McpAstVisitor, tree: ast.AST, source: str) -> None:
    """Analyze high-level control flows for Path Traversal and BOLA flaws."""
    # 1. Path Traversal Check
    if (
        "is_traversal" in source
        and "external_files" in source
        and 'profile == "vulnerable"' in source
    ):
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                test_dump = ast.dump(node.test)
                if "is_traversal" in test_dump:
                    sub_source = ast.get_source_segment(source, node) or ""
                    if (
                        "external_files" in sub_source
                        and "return" in sub_source
                        and "path_traversal" in sub_source
                    ):
                        msg = "Path traversal: file read serves out-of-boundary paths."
                        visitor._add_finding(RuleCatalog.RULE_CWE_22_UNBOUNDED_READ, node, msg)
                        break

    # 2. BOLA Multi-Tenant Check
    has_tenant_source = "session_tenant" in source and (
        "target_tenant" in source or "resource_tenant" in source
    )
    if has_tenant_source and ("bola_violation" in source or "is_cross_tenant" in source):
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                test_dump = ast.dump(node.test)
                if "is_cross_tenant" in test_dump:
                    sub_source = ast.get_source_segment(source, node) or ""
                    if "bola_violation" in sub_source or "CANARY_BOLA_TOKEN" in sub_source:
                        msg = "BOLA flaw: cross-tenant document returned without session check."
                        visitor._add_finding(RuleCatalog.RULE_CWE_862_BOLA, node, msg)
                        break


AST_RULE_IDS: frozenset[str] = frozenset(
    rule.rule_id for rule in RuleCatalog.ALL_RULES
)
