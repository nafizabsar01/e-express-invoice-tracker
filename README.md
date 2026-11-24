# e-Express Invoice Tracker — ESCM LLC

Web app for the e-Express Data Entry Project invoice register and management dashboard.

- **Front end** (this repo, served by GitHub Pages): `index.html`, `config.js`, `logo.png`, `apple-touch-icon.png`, `manifest.webmanifest`.
- **Back end**: `Code.gs` + `appsscript.json` run in Google Apps Script. The data stays in a private Google Sheet.

No invoice data, user lists or spreadsheet IDs are stored in this repository.

## Security model
- Users sign in with "Sign in with Google". Every API request carries the Google ID token.
- Apps Script verifies each token with Google (audience = this app's client ID, issuer, expiry, verified email), then checks the email against the `App_Users` tab. Roles and batch/record access are enforced on the server for every read, write, export and dashboard request.
- The spreadsheet is never shared with app users. The script runs as the owner.
