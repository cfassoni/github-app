# Engineering Guidelines & Agent Constraints

## Core Protocol

- **Artifact Language:** ALL repo and task artifacts (code, docs, tests, commits, PRs, plans, scratch) MUST be **en-US** without exception.
- **Chat Language:** Conversational turns follow the active user session language (e.g. pt-BR). Never author or translate repo artifacts into chat language.
- **Decision Benchmark:** Reject speculative features, wrappers, and config. Minimum code to solve the problem.
- **Protocol Fidelity:** Inviolable fidelity to authentic upstream API contracts (GitHub REST API, RFC 7519 JWT, Git credential helper protocol).
- **Security Invariant:** Never log, print, commit, or persist private keys, JWTs, or access tokens in repository files or memory.

## Output Efficiency & Anti-Fluff Protocol

- **No Conversational Fluff:** Omit pleasantries, acknowledgments, meta-commentary, and conversational filler.
- **Direct Action Starts:** Jump directly into the file diff, command execution, or structured proposal from the first character.
- **No Self-Recap:** Never summarize what you just did unless explicitly requested. Deliver output and stop.
- **Concise Failure Modes:** State root cause and proposed fix in 1–2 sentences, not narrative prose.

## Git & Governance Directives

- **Branching & Commits:** Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`) and SemVer.
- **Single-Issue PR Invariant:** Exactly 1 issue/task per branch and PR. PRs must be atomic and focused.
- **Ephemeral Credentials:** Authenticate Git and GitHub CLI operations via `github-app` CLI and its credential helper.
- **Quality Gates:** 100% statement coverage on changed code via `pytest --cov=github_app --cov-report=term-missing` and clean lint via `ruff check`.
