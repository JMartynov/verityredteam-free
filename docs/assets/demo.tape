Output "/out/demo_raw.gif"
Set Shell "bash"
Set Width 900
Set Height 480
Set FontSize 12
Set Padding 12
Set Framerate 16
Set TypingSpeed 35ms
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"

Hide
Type "cd /demo && clear"
Enter
Show

# Scene 1: workstation config audit (scrubbed secret + OSV CVE)
Type "# [1/4] Audit local IDE config: secrets, shell wrappers & CVEs"
Enter
Sleep 600ms
Type "verity scan --config-file ~/.cursor/mcp.json --fail-on-findings"
Enter
Sleep 4.5s

# Scene 2: live poisoned stdio MCP probe
Hide
Type "clear"
Enter
Show
Type "# [2/4] Probe live stdio MCP server for tool poisoning & SSRF"
Enter
Sleep 600ms
Type 'verity test --command "python3 vuln_stdio_mcp.py"'
Enter
Sleep 4s

# Scene 3: deterministic SQL AST guard (block vs pass)
Hide
Type "clear"
Enter
Show
Type "# [3/4] Block LLM SQL injection deterministically (sqlglot AST)"
Enter
Sleep 500ms
Type 'verity test --sql "SELECT id FROM users; DROP TABLE users;--"'
Enter
Sleep 2.2s
Type 'verity test --sql "SELECT id, email FROM orders WHERE tenant_id = :id"'
Enter
Sleep 3.2s

# Scene 4: Python AST CI gate + zero-Docker 4-target demo
Hide
Type "clear"
Enter
Show
Type "# [4/4] Python AST CI gate (CWE-94/78/502) & 4-target demo"
Enter
Sleep 500ms
Type "verity scan --path ast_vuln_server.py --config-file empty.json --offline --fail-on-findings"
Enter
Sleep 3.8s

Hide
Type "clear"
Enter
Show
Type "verity test --demo"
Enter
Sleep 4.5s
