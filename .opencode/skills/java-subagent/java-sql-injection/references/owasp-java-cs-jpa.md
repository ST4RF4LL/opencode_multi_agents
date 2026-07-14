# OWASP Java Security Cheat Sheet — JPA

Source: [OWASP Java Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html) (JPA section)

## Symptom

Untrusted input is used to build a **JPA QL (JPQL/HQL) string**, not only native SQL. Same failure mode as SQL string concatenation: the attacker controls query structure.

## Prevention

**JPQL Query Parameterization** — keep the query text constant; bind values with named (or positional) parameters via `setParameter`.

## Example (safe)

```java
em.createQuery("select c from Color c where c.friendlyName = :colorName")
  .setParameter("colorName", untrustedColorName);
```

## Mapping in this skill

| Concept | Skill artifact |
|---------|----------------|
| JPQL string concat | subtype `jpa-jpql-injection`, case-004, `P06_JpaJpqlConcat` |
| Named param fix | `N06_JpaJpqlNamedParam`, hibernate-jpa `safe_patterns` |
| Native SQL concat | subtype `orm-native-query`, case-003, `P04_JpaNativeConcat` |
| Sink | `EntityManager.createQuery` / `Session.createQuery` arg 1 |
