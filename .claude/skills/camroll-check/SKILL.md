---
name: camroll-check
description: Scan the user's own exported photos/screenshots folder for secrets (seed phrases, cards, IBANs, passports, 2FA codes, API keys, passwords) with the local camroll-check tool, then walk them through cleanup and the iPhone privacy checklist.
---

# camroll-check

Use when the user wants to check their own photos, camera roll, or screenshots for sensitive data.

## Rules
- Only scan folders the user points to and says are theirs. Do not scan other people's devices or backups.
- Never open, Read, or display the original flagged images or their OCR text. Work only from the masked console summary and `findings.json`. The point of the tool is that the secret never leaves the user's screen.
- Do not delete anything yourself. Give the user the list and let them delete on the phone.

## Steps
1. Check the tool is installed: `python -c "import camroll_check"`. If not: `pip install -e .` from the repo root (on macOS add `".[mac]"`). On Linux/Windows make sure `tesseract` is on PATH.
2. If the user has no export yet, explain the export step for their OS from README.md ("get your iPhone photos onto the computer").
3. Run: `python -m camroll_check.scan "<folder>" --out "<folder>/../camroll-report"` (add `--since YYYY-MM-DD` if they want a date range). Large libraries take a while; run in the background and report progress lines.
4. Summarise from the console output: counts by kind and severity, and the file names of high-severity items. Tell them to open `report.html` to see blurred previews.
5. Give the action list from README.md "after the scan", ordered by what was found (seed phrase first, then keys/tokens, ID, cards, IBAN, passwords).
6. Walk them through CHECKLIST.md on the phone, one section at a time, asking what they see.
7. At the end remind them to delete the export folder and the report.
