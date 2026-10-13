# Documentation archive

These documents record completed transitions. They are not maintained as
current installation instructions. Use the [documentation index](../README.md)
for supported behavior and [release readiness](../builds.md#release-verification) for
unfinished release and deployment work.

| Document | Historical scope |
| --- | --- |
| [Architecture upgrade status](container-architecture-upgrade-plan.md) | Phase mapping and implementation status at consolidation |
| [ovpncp-to-Rivet rename](rivet-rename.md) | One-time upgrade instructions for installations using the former names |

The full original architecture plan, completed frontend/native plans, and
superseded build/verification logs remain in Git history. For example:

```bash
git show 8f506b9:docs/container-architecture-upgrade-plan.md
git show 8f506b9:docs/frontend-implementation-plan.md
git show 8f506b9:docs/native-installation-plan.md
```

Historical verification applies only to the artifacts and environments tested
at that time; it does not approve a current release or deployment.
