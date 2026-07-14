# False-Positive Patterns: java-xpath-injection

- **language**: java
- **skill**: `java-xpath-injection`
- **weakness**: `xpath-injection`
- **dimension**: D1
- **source**: vuln_skill_builder `analysis/false-positive-patterns.yaml`

## Not a vulnerability

### `constant-xpath-with-variable-resolver`
- Pattern: XPath.compile constant template with $var and XPathVariableResolver binding
- Reason: user input cannot change query structure

### `constant-evaluate-expression`
- Pattern: evaluate/compile with fully constant expression string
- Reason: no external influence on XPath structure

### `expression-allowlist`
- Pattern: filter/path mapped through immutable allowlist/enum to constant fragments
- Reason: attacker selects among fixed safe expressions only

### `test-only-xpath`
- Pattern: XPath helper only referenced from test sources
- Reason: not production reachable

## Needs deeper review

### `compile-but-concat`
- Pattern: XPath.compile(expr) where expr includes + / format / append
- Reason: false sense of safety if VariableResolver is also present but unused for the slot

### `predicate-param`
- Pattern: "[@id='" + requestParam + "']"
- Reason: classic predicate injection

### `login-xpath`
- Pattern: user/password concatenated into XPath auth check
- Reason: boolean logic bypass subtype

### `wrapper-util`
- Pattern: custom XPathUtil/XmlHelper query(String)
- Reason: sink is indirection; expand to real compile/evaluate

### `partial-binding`
- Pattern: some values bound via resolver but other path fragments still concatenated
- Reason: partial parameterization

