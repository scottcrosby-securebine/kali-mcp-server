# Issue tracker: GitHub

Issues and PRDs for this repository live in GitHub Issues. Use the `gh` CLI for tracker operations and infer the repository from `git remote -v`.

## Conventions

- Create issues with `gh issue create`.
- Read issues and comments with `gh issue view <number> --comments`.
- List issues with `gh issue list` and request JSON fields when automating.
- Comment with `gh issue comment`; apply or remove labels with `gh issue edit`.
- Close resolved issues with `gh issue close` and a final explanatory comment.

## Pull requests as a triage surface

External pull requests are **not** a request or triage surface. Triage skills process GitHub Issues only.

## Publishing

When a skill says to publish a specification, PRD, epic, or ticket to the issue tracker, create a GitHub issue in this repository.

## Dependencies

Prefer GitHub sub-issues and native issue dependencies when supported. If the repository does not expose those features, use a task list in the parent issue and a `Blocked by: #<number>` line in child issues. A ticket is actionable only after all referenced blockers are closed.
