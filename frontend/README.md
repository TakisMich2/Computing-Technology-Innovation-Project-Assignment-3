# PhishCheck – front end

React front end for the Phishing URL Detection System. 

## Scripts

| Command | What it does |
|---|---|
| `npm ci` | Install the exact versions in `package-lock.json` |
| `npm run build` | Production build into `dist/`, served by the back end at http://127.0.0.1:8000 |
| `npm run dev` | Dev server at http://localhost:5173, forwarding `/api` to the back end on port 8000 |

Requires Node.js 22.12 or newer.

## Where each requirement is met

| Requirement | Where |
|---|---|
| Input validated before sending | `src/utils/validateUrl.js`, `src/components/UrlForm.jsx` (usability only; the back end re-validates everything) |
| Result most prominent, with confidence | `src/components/ResultPanel.jsx`, `TrustGauge.jsx` |
| Loading, success and error states | `src/pages/HomePage.jsx`, `src/components/StatusMessages.jsx` (including "server busy" for 503 and an early "server offline" notice from `GET /api/health`) |
| 404 page | `src/pages/NotFoundPage.jsx` (any unknown address) |
| Fallback page for unexpected errors | `src/components/ErrorBoundary.jsx` (try `/dev/crash` in dev) |
| Visualisations (titles, labels, legends, tooltips) | `src/components/charts/`: model confidence, warnings by URL part, history trust scores |
| Consistent design | Tokens at the top of `src/styles/global.css` |
| Responsive | Breakpoints at 480/600/640/880 px; tested at phone and desktop widths |
| Accessibility | Labelled inputs, AA contrast, skip link, focus rings, keyboard-navigable charts (`accessibilityLayer`), screen-reader summaries |
| History and export (FR7/FR8) | `src/pages/HistoryPage.jsx`, `src/utils/history.js` |
