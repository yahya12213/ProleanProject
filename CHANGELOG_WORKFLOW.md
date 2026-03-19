# Changelog workflow

This project uses `Summary of Features & Changes.txt` as the canonical change log.

## Rule
- For every **feature**, **fix**, **config**, or **refactor**, append one entry (UTC date).

## Helper (optional)
Use the script to append a correctly formatted entry:

- `powershell -ExecutionPolicy Bypass -File scripts/add-change.ps1 -Area Prolean -Type Fix -What "..." -Why "..." -Validation "Django system check"`

## Git hook (recommended)
To enforce that the changelog is updated on commits:

- `git config core.hooksPath .githooks`

To bypass once (not recommended):
- `SKIP_CHANGELOG=1 git commit ...`

