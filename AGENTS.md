# Repository Guide for Coding Agents

This file is the self-contained source of truth for agents working in this
repository. It includes the project context, engineering constraints, and
verification workflow needed to make changes without consulting other
instruction files.

## Project Purpose

`ovpncp` is an API-driven OpenVPN control panel for restricted IoT and edge
networks. It manages VPN clients, certificate packaging and distribution,
fixed IP assignments, routes, and fine-grained `iptables` access rules.

The primary users are developers, system administrators, and security
engineers. The primary interfaces are the REST API and CLI. Optimize both for
clear naming, consistent behavior, few operational steps, and actionable
errors.

Key integrations and capabilities include:

- FastAPI endpoints and RFC 7807 problem responses
- SQLModel persistence with SQLite by default and optional MySQL/PostgreSQL
- OpenVPN, Easy-RSA client import, `iptables`, and `iproute2`
- Optional Azure Entra ID authentication
- Optional Azure Blob Storage certificate management

Future-looking ideas are not current requirements. Do not introduce new cloud
providers, VPN protocols, identity providers, or observability platforms
unless the task explicitly calls for them.

## Repository Layout

- `src/sciaiot/ovpncp/`: application package
- `src/sciaiot/ovpncp/routes/`: FastAPI route handlers
- `src/sciaiot/ovpncp/data/`: persistence models and database behavior
- `src/sciaiot/ovpncp/middlewares/`: Azure security and storage integrations
- `src/sciaiot/ovpncp/utils/`: OpenVPN, firewall, routing, and logging helpers
- `src/sciaiot/ovpncp/scripts/`: OpenVPN connection hook scripts
- `tests/`: pytest test suite
- `pyproject.toml`: package metadata and pytest configuration
- `requirements*.txt`: runtime and development dependencies

## Technology and Compatibility

- Use Python 3.14+ and CPython.
- Keep FastAPI, Uvicorn, Pydantic/SQLModel, and setuptools as the core stack.
- Use PyYAML for YAML configuration.
- Use `python-jose` and `cryptography` for the existing security integration.
- Treat OpenVPN, `iptables`, and `iproute2` interactions as privileged,
  security-sensitive system boundaries.
- Document a proposed technology-stack change before implementing it, and do
  not add a dependency when the standard library or an existing dependency is
  sufficient.

## Working Rules

1. Inspect nearby implementation and tests before editing. Follow established
   repository patterns.
2. Preserve unrelated user changes. Do not switch branches, pull, commit,
   create git notes, or open a pull request unless the user explicitly asks.
3. When a task has an associated track plan, use that plan as the task source
   of truth and keep its status accurate. Do not create process artifacts for
   small untracked changes unless requested.
4. Use test-driven development for behavior changes:
   - add or update a test that expresses the expected behavior;
   - run it and confirm the relevant failure when practical;
   - implement the smallest coherent fix;
   - rerun focused tests, then the broader suite;
   - refactor only while tests remain green.
5. Prefer non-interactive commands. Set `CI=true` for any tool that would
   otherwise enter watch mode.
6. Keep documentation synchronized with user-visible behavior,
   configuration, installation steps, and API changes.

## Design and Code Style

- Favor readable, simple, modular code with low coupling.
- Consolidate business logic into clear abstractions instead of duplicating it
  across routes, middleware, and utilities.
- Use type annotations extensively, especially on public APIs.
- Use `snake_case` for modules, functions, methods, and variables;
  `PascalCase` for classes; and `ALL_CAPS_WITH_UNDERSCORES` for constants.
- Use four spaces, never tabs. Keep lines at or below 80 characters unless an
  existing formatter necessarily produces otherwise.
- Group imports as standard library, third party, then application imports.
  Prefer `import package` and use `from package import module` primarily for
  submodules.
- Use f-strings. Avoid mutable default arguments, mutable global state, bare
  `except`, clever comprehensions, and implicit `None` checks.
- Public modules, classes, functions, and methods need triple-double-quoted
  docstrings. Explain intent and rationale; include `Args:`, `Returns:`, and
  `Raises:` sections when applicable.
- Executable Python modules should expose a `main()`-style entry point guarded
  by `if __name__ == "__main__":` when direct execution is supported.
- Let Ruff be the formatting and linting authority. Do not introduce a
  separate Pylint requirement.

## API and Error Behavior

- Keep endpoints, parameters, models, and responses predictable and
  self-documenting.
- Preserve RFC 7807-compatible error responses.
- Errors must say what failed, why it failed when safe to disclose, and what
  the caller can do next.
- Validate at the boundary and keep response shapes consistent.
- Test both successful and unsuccessful flows, including authentication,
  authorization, persistence, and system-command failures where relevant.

## Security Requirements

- Strictly validate every value used in a command, path, route, firewall rule,
  certificate operation, or database query.
- Prevent command injection, path traversal, SQL injection, and unsafe
  privilege escalation. Prefer argument arrays and constrained domain types
  over interpolated shell strings.
- Never hardcode, log, or return secrets, access tokens, SAS URLs, private
  certificate material, or other credentials.
- Mask or redact sensitive data, including security tokens and IP addresses,
  in logs and error details.
- Fail securely. Invalid security configuration must not silently disable
  authentication or authorization.
- Mock privileged system operations and external Azure services in unit tests.
  Do not alter the host firewall, routes, VPN service, cloud resources, or
  real certificate stores during ordinary tests.

## Tests and Quality Gates

Install development dependencies with:

```bash
python -m pip install -r requirements-dev.txt
```

Use focused tests while developing, then run the complete quality checks:

```bash
ruff format --check .
ruff check .
mypy .
pytest --cov=src/sciaiot/ovpncp --cov-report=term-missing
```

Use `ruff format .` to apply formatting. Target more than 80% coverage for new
or changed code. Every application module should have meaningful test
coverage, with fixtures for setup/teardown and mocks for external
dependencies. Include success, failure, edge, database transaction, and
security cases as appropriate.

Before declaring work complete, verify:

- relevant focused tests and the full applicable suite pass;
- Ruff formatting and lint checks pass;
- mypy passes;
- changed code has adequate coverage;
- public APIs are typed and documented;
- user-facing documentation is current;
- no secret exposure or security regression was introduced.

If a check cannot run because the environment lacks a service, privileged
access, or a dependency, report exactly what was and was not verified.

## Change Handoff

Summarize the behavior changed, identify important files, and list the exact
checks run with their results. Call out remaining risks or manual verification
steps. When the user requests commits, use Conventional Commit messages such
as `feat(scope): description`, `fix(scope): description`, or
`docs(scope): description`.
