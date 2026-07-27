# Domain Docs

This repo uses a single-context domain-documentation layout.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root.
- **`docs/adr/`** — if it exists, read ADRs that touch the area you're about to work in.

If either path doesn't exist, **proceed silently**. Don't flag its absence or suggest creating it upfront. Skill(domain-modeling) creates domain documentation lazily when terms or decisions get resolved.

## File structure

```text
/
├── CONTEXT.md
├── docs/adr/
│   ├── 001-event-sourced-orders.md
│   └── 002-postgres-for-write-model.md
└── src/
```

## Use the glossary's vocabulary

When your output names a domain concept—in an issue title, refactor proposal, hypothesis, or test name—use the term defined in `CONTEXT.md`. Don't drift to synonyms the glossary explicitly avoids.

If the glossary doesn't define the concept, reconsider whether you're inventing language the project doesn't use or note the gap for Skill(domain-modeling).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0007 (event-sourced orders) — but worth reopening because…_
