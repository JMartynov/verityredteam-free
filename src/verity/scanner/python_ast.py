"""Native Python AST visitor analyzing MCP server tool definitions and call expressions."""

from __future__ import annotations

import ast
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

from verity.scanner.models import AstFinding
from verity.scanner.rules import RuleCatalog, RuleDefinition

_PATH_SINKS: frozenset[str] = frozenset(
    {"open", "Path", "pathlib.Path", "os.path.join", "posixpath.join", "os.open"}
)
_SQL_OBJECT_HINTS: tuple[str, ...] = (
    "cursor",
    "connection",
    "conn",
    "db",
    "session",
    "engine",
    "store",
    "client",
)
_ID_LOOKUP_PREFIXES: tuple[str, ...] = ("get_", "fetch_", "find_", "read_")
_ID_LOOKUP_OBJECTS: frozenset[str] = frozenset(
    {"session", "cursor", "repo", "db", "store", "repository", "client"}
)
_ID_LOOKUP_SUBSCRIPTS: frozenset[str] = frozenset(
    {
        "documents",
        "records",
        "items",
        "objects",
        "files",
        "store",
        "_store",
        "db",
        "table",
        "rows",
    }
)
_TENANT_GUARD_NAMES: frozenset[str] = frozenset(
    {"session_tenant", "current_user", "owner_id", "tenant_id"}
)
_TENANT_GUARD_ATTRS: frozenset[str] = frozenset({"owner_id", "tenant_id"})
_AUTH_GUARD_CALLS: frozenset[str] = frozenset(
    {"check_access", "authorize", "verify_owner"}
)

_RULE_CWE_89_SQLI: RuleDefinition = replace(
    RuleCatalog.RULE_CWE_94_EVAL,
    rule_id="VERITY-AST-CWE-89-SQLI",
    cwe_id="CWE-89",
    title="SQL Injection via Dynamic Query Construction",
    description=(
        "A SQL query is assembled by interpolating values with an f-string, "
        "str.format, or the % operator, allowing SQL injection."
    ),
    remediation=(
        "Use parameterized queries or prepared statements and never interpolate "
        "untrusted values into SQL text."
    ),
)


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
        if _function_is_tool(node):
            self.current_tool = node.name
        self.generic_visit(node)
        self.current_function = prev_func
        self.current_tool = prev_tool

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Track async function and MCP tool scope while traversing AST."""
        prev_func = self.current_function
        prev_tool = self.current_tool
        self.current_function = node.name
        if _function_is_tool(node):
            self.current_tool = node.name
        self.generic_visit(node)
        self.current_function = prev_func
        self.current_tool = prev_tool

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
        func_name = node.func.id if isinstance(node.func, ast.Name) else ""
        full_call = _call_dotted_name(node, self.imports)

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

    _analyze_functions(visitor, tree)
    return visitor.findings


def _call_dotted_name(node: ast.Call, imports: dict[str, str]) -> str:
    parts: list[str] = []
    curr: ast.AST = node.func
    while isinstance(curr, ast.Attribute):
        parts.insert(0, curr.attr)
        curr = curr.value
    if isinstance(curr, ast.Name):
        parts.insert(0, curr.id)
    if not parts:
        return ""
    raw = ".".join(parts)
    head, _, rest = raw.partition(".")
    resolved = imports.get(head, head)
    return f"{resolved}.{rest}" if rest else resolved


def _function_is_tool(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
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
            return True
    name = node.name
    return name.startswith("tool_") or "handle_" in name or name in ("call", "execute_tool")


def _function_params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    params = {a.arg for a in node.args.args}
    params |= {a.arg for a in node.args.posonlyargs}
    params |= {a.arg for a in node.args.kwonlyargs}
    params.discard("self")
    params.discard("cls")
    return params


def _iter_own_nodes(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Iterator[ast.AST]:
    stack: list[ast.AST] = list(reversed(func_node.body))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield node
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _expr_references_tainted(expr: ast.AST, tainted: set[str]) -> bool:
    return any(isinstance(n, ast.Name) and n.id in tainted for n in ast.walk(expr))


def _add_function_finding(
    visitor: McpAstVisitor,
    rule: RuleDefinition,
    node: ast.AST,
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    message: str,
) -> None:
    prev_func = visitor.current_function
    prev_tool = visitor.current_tool
    visitor.current_function = func_node.name
    visitor.current_tool = func_node.name if _function_is_tool(func_node) else None
    visitor._add_finding(rule, node, message)
    visitor.current_function = prev_func
    visitor.current_tool = prev_tool


def _analyze_functions(visitor: McpAstVisitor, tree: ast.Module) -> None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _analyze_cwe22(visitor, node)
            _analyze_cwe89(visitor, node)
            _analyze_cwe862(visitor, node)


def _analyze_cwe22(
    visitor: McpAstVisitor, func_node: ast.FunctionDef | ast.AsyncFunctionDef
) -> None:
    params = _function_params(func_node)
    if not params:
        return
    nodes = list(_iter_own_nodes(func_node))

    assign_pairs: list[tuple[str, ast.AST]] = []
    for node in nodes:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assign_pairs.append((target.id, node.value))
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            assign_pairs.append((node.target.id, node.value))

    tainted: set[str] = set(params)
    changed = True
    while changed:
        changed = False
        for name, value in assign_pairs:
            if name not in tainted and _expr_references_tainted(value, tainted):
                tainted.add(name)
                changed = True

    call_names = [
        _call_dotted_name(n, visitor.imports) for n in nodes if isinstance(n, ast.Call)
    ]
    has_resolve = any(n == "resolve" or n.endswith(".resolve") for n in call_names)
    has_relative = any(
        n == "is_relative_to" or n.endswith(".is_relative_to") for n in call_names
    )
    has_realpath = any(
        n == "os.path.realpath" or n.endswith(".realpath") for n in call_names
    )
    has_commonpath = any(
        n == "os.path.commonpath" or n.endswith(".commonpath") for n in call_names
    )
    if (has_resolve and has_relative) or has_realpath or has_commonpath:
        return

    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        if _call_dotted_name(node, visitor.imports) not in _PATH_SINKS:
            continue
        candidates = list(node.args) + [kw.value for kw in node.keywords]
        if not any(_expr_references_tainted(arg, tainted) for arg in candidates):
            continue
        _add_function_finding(
            visitor,
            RuleCatalog.RULE_CWE_22_UNBOUNDED_READ,
            node,
            func_node,
            "Untrusted input reaches a path sink without containment (CWE-22).",
        )
        return


def _is_sql_sink(name: str) -> bool:
    if not name:
        return False
    parts = name.split(".")
    last = parts[-1]
    if last in ("execute", "executemany"):
        return True
    if last in ("raw", "text"):
        prefix = ".".join(parts[:-1]).lower()
        return any(hint in prefix for hint in _SQL_OBJECT_HINTS)
    return False


def _is_dynamic_sql(
    expr: ast.AST, assign_map: dict[str, ast.AST], depth: int = 0
) -> bool:
    if depth > 4:
        return False
    if isinstance(expr, ast.Name) and expr.id in assign_map:
        return _is_dynamic_sql(assign_map[expr.id], assign_map, depth + 1)
    if isinstance(expr, ast.JoinedStr):
        return any(
            isinstance(v, ast.FormattedValue) and not isinstance(v.value, ast.Constant)
            for v in expr.values
        )
    if isinstance(expr, ast.Call):
        func = expr.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "format"
            and isinstance(func.value, ast.Constant)
            and isinstance(func.value.value, str)
        ):
            return bool(expr.args or expr.keywords)
        return False
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
        left = expr.left
        if isinstance(left, ast.Constant) and isinstance(left.value, str):
            return not isinstance(expr.right, ast.Constant)
    return False


def _analyze_cwe89(
    visitor: McpAstVisitor, func_node: ast.FunctionDef | ast.AsyncFunctionDef
) -> None:
    nodes = list(_iter_own_nodes(func_node))
    assign_map: dict[str, ast.AST] = {}
    for node in nodes:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            assign_map[node.targets[0].id] = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            assign_map[node.target.id] = node.value

    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        if not _is_sql_sink(_call_dotted_name(node, visitor.imports)):
            continue
        if not node.args:
            continue
        if not _is_dynamic_sql(node.args[0], assign_map):
            continue
        _add_function_finding(
            visitor,
            _RULE_CWE_89_SQLI,
            node,
            func_node,
            "Dynamic SQL built with string interpolation; use parameterized queries.",
        )


def _looks_like_id_lookup(node: ast.Call, cn: str, params: set[str]) -> bool:
    if not node.args and not node.keywords:
        return False
    parts = cn.split(".")
    if len(parts) < 2:
        return False
    if not parts[-1].startswith(_ID_LOOKUP_PREFIXES):
        return False
    obj = parts[-2]
    return obj in params or obj in _ID_LOOKUP_OBJECTS


def _looks_like_id_subscript(node: ast.Subscript) -> bool:
    if not isinstance(node.slice, ast.Name):
        return False
    value = node.value
    if isinstance(value, ast.Attribute):
        return value.attr in _ID_LOOKUP_SUBSCRIPTS
    if isinstance(value, ast.Name):
        return value.id in _ID_LOOKUP_SUBSCRIPTS
    return False


def _analyze_cwe862(
    visitor: McpAstVisitor, func_node: ast.FunctionDef | ast.AsyncFunctionDef
) -> None:
    if not _function_is_tool(func_node):
        return
    params = _function_params(func_node)
    nodes = list(_iter_own_nodes(func_node))

    lookup_node: ast.AST | None = None
    has_guard = False
    has_vuln_return = False

    for node in nodes:
        if isinstance(node, ast.Call):
            cn = _call_dotted_name(node, visitor.imports)
            if lookup_node is None and _looks_like_id_lookup(node, cn, params):
                lookup_node = node
            if cn and cn.split(".")[-1] in _AUTH_GUARD_CALLS:
                has_guard = True
        elif (isinstance(node, ast.Name) and node.id in _TENANT_GUARD_NAMES) or (
            isinstance(node, ast.Attribute) and node.attr in _TENANT_GUARD_ATTRS
        ):
            has_guard = True
        elif isinstance(node, ast.Subscript):
            if lookup_node is None and _looks_like_id_subscript(node):
                lookup_node = node
        elif (
            isinstance(node, ast.If)
            and "vulnerable" in ast.dump(node.test)
            and any(
                isinstance(d, ast.Return) for stmt in node.body for d in ast.walk(stmt)
            )
        ):
            has_vuln_return = True

    if lookup_node is None:
        return
    if has_guard and not has_vuln_return:
        return
    _add_function_finding(
        visitor,
        RuleCatalog.RULE_CWE_862_BOLA,
        lookup_node,
        func_node,
        "Tool looks up a record without tenant or ownership authorization.",
    )


AST_RULE_IDS: frozenset[str] = frozenset(
    rule.rule_id for rule in RuleCatalog.ALL_RULES
)
