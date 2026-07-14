# False-Positive Patterns: java-ldap-injection

- **language**: java
- **skill**: `java-ldap-injection`
- **weakness**: `ldap-injection`
- **dimension**: D1
- **source**: vuln_skill_builder `analysis/false-positive-patterns.yaml`

## Not a vulnerability

### `constant-filter-with-filterargs`
- Pattern: DirContext.search with constant filter template and filterArgs binding only
- Reason: user input cannot change filter structure

### `equals-filter-api`
- Pattern: EqualsFilter / LikeFilter / LdapQueryBuilder.where().is() without raw concat
- Reason: Spring LDAP encodes assertion values

### `ldap-encoder-value-only`
- Pattern: LdapEncoder.filterEncode applied to value before insertion into fixed template
- Reason: metacharacters escaped in value context

### `allowlisted-username`
- Pattern: username mapped through immutable allowlist/enum before filter use
- Reason: attacker selects among fixed safe values only

## Needs deeper review

### `concat-filter-login`
- Pattern: "(uid=" + username + ")" style auth filter
- Reason: classic login bypass via * or )(|(uid=*

### `hardcoded-filter-concat`
- Pattern: new HardcodedFilter with + or format
- Reason: bypasses structured Filter API safety

### `dn-concat`
- Pattern: "uid=" + user + ",ou=people,..."
- Reason: DN injection / search base escape

### `partial-replace`
- Pattern: replace only * or only parentheses
- Reason: incomplete; \\ and NUL often missed

### `wrong-encoder-context`
- Pattern: filterEncode used for DN or nameEncode for filter values only
- Reason: context mismatch may leave metacharacters active

### `wrapper-ldap-service`
- Pattern: custom LdapUtil/DirectoryService search(String)
- Reason: sink is indirection; expand to real JNDI/Spring LDAP call

