# PhishCheck

PhishCheck checks a submitted URL with a trained phishing-detection model and
returns a trust score and explanations. The backend analyses the URL as text;
it does not visit the submitted address. Check history stays in the browser.

## Run locally (Windows PowerShell)

Requirements: Python 3.14 and Node.js 22.12 or newer.

1. Install and configure the backend:

   ```powershell
   cd backend
   py -3.14 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   Copy-Item .env.example .env
   ```

2. Build the frontend (in another terminal, from the project root):

   ```powershell
   cd frontend
   npm ci
   npm run build
   ```

3. Start the server from `backend/`:

   ```powershell
   python run.py
   ```

   Open http://127.0.0.1:8000. The backend serves the built frontend and API.

For frontend development, leave the backend running and start Vite in another
terminal with `cd frontend` and `npm run dev`. Open http://localhost:5173;
Vite forwards API requests to the backend.

## API

- `POST /api/assess` with `{"url":"https://example.com"}` returns a trust score,
  phishing probability, prediction and warnings.
- `GET /api/health` reports whether the model is loaded.

Backend tests can be run from `backend/` after installing the development
dependencies with `python -m pip install -r requirements-dev.txt`, then
`python -m pytest`.
