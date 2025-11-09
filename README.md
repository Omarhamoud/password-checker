# Password Checker (Netlify) — English UI

Changes requested:
- English-only UI and labels.
- User-data inputs (name + manual birthdate text field) placed directly above the "Suggest password" button.
- Suggestion uses those inputs as a seed; backend verifies suggestion is not in HIBP and returns zxcvbn score.

Files:
- public/index.html
- netlify/functions/check-password.js
- netlify.toml
- package.json

Deploy:
- Push to GitHub and import to Netlify, or use Netlify CLI:
  netlify deploy --prod --dir=public --functions=netlify/functions