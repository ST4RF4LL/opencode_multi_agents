# False-Positive Patterns: java-command-injection

- **language**: java
- **skill**: `java-command-injection`
- **weakness**: `command-injection`
- **dimension**: D1
- **source**: vuln_skill_builder `analysis/false-positive-patterns.yaml`

## Not a vulnerability

### `constant-command`
- Pattern: Runtime.exec / ProcessBuilder with fully constant argv and no user influence
- Reason: user input cannot change command or arguments

### `processbuilder-list-validated`
- Pattern: ProcessBuilder list form, fixed binary, user input is single arg with strict allowlist
- Reason: no shell; attacker cannot inject metacharacters or extra tokens

### `java-api-replacement`
- Pattern: no OS process; pure Java API used
- Reason: not command injection

### `fixed-command-map`
- Pattern: user selects id mapped to predefined constant command/args
- Reason: attacker selects among fixed safe operations only

## Needs deeper review

### `runtime-exec-concat`
- Pattern: Runtime.exec(string + input) or format into command string
- Reason: classic CMDi; high priority

### `processbuilder-sh-c`
- Pattern: ProcessBuilder shell wrapper with -c /c
- Reason: shell injection even if ProcessBuilder API is used

### `array-exec-but-shell`
- Pattern: Runtime.exec(new String[]{"sh","-c", input})
- Reason: array form does not make shell safe

### `argument-injection`
- Pattern: fixed binary but user-controlled flags/operands
- Reason: may still be security-relevant without shell

### `commons-exec-parse`
- Pattern: CommandLine.parse(dynamicString)
- Reason: string parsing; confirm taint

### `wrapper-util`
- Pattern: custom ShellUtil/ProcessHelper execute(String)
- Reason: sink is indirection; expand to real executor

