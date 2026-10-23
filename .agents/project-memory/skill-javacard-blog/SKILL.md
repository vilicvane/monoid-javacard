---
name: project-memory-javacard-blog
description: Record interesting Java Card questions and verified findings for future blog posts. Use when development reveals a useful mechanism, counterintuitive result, or measured tradeoff worth explaining later.
---

# Monoid Java Card blog notes

Source: `../records.md` and record173. Treat the index, related numeric records and their references as authoritative; this skill is a workflow snapshot.

- During authorized development, notice questions and findings that would interest a future reader: a surprising runtime behavior, an assumption contradicted by measurement, or a concrete implementation tradeoff.
- Find the existing numeric record for that topic through `records.md`. Add or update its `## 博客兴趣点` section and add `[blog]` to its index entry. Create a new numeric record only when no existing topic fits, following Project Memory. Keep evidence and the blog angle together rather than maintaining duplicate research notes.
- Keep the section concise and self-contained:
  - **切入问题**: What is interesting or counterintuitive, and why would a reader care?
  - **关键事实**: The observations and reasoning already established. Separate specification guarantees, source analysis, simulator results, physical-card measurements and unresolved hypotheses.
  - **适用边界**: Relevant card/runtime, workload, lifecycle and measurement limits. Use the project's confirmed physical-card behavior baseline, record actual coverage, and distinguish that baseline from specification guarantees.
  - **参考**: The related record sections, source locations and specifications. Research artifacts can supplement the record, but must not be the only place containing its conclusion or essential evidence.
- Merge later evidence into the same topic and revise outdated conclusions explicitly. Preserve unresolved questions as unresolved; do not manufacture a conclusion or a dramatic claim.
- Do not divert the development task into extra research just to complete a blog note. Do not draft or publish a full post unless requested.

Find recorded topics with `rg -n '\[blog\]|^## 博客兴趣点' .agents/project-memory`.
