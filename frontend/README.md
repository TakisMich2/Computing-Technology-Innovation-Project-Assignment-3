# PhishCheck Front End

This is the React app for PhishCheck. It lets you check a URL, see its trust
score and any warning signs, and review or export your check history.

For instructions on running the full app, see the
[main README](../README.md). For details about the security design, see
[SECURITY.md](../SECURITY.md).

## Getting started

You'll need Node.js 22.12 or newer.

```bash
npm ci
npm run dev
```

The development server will print a local address, usually
http://localhost:5173. For live URL checks, start the back end as described in
the main README; requests to `/api` are forwarded to it.

To run a demo without the back end, use `npm run dev:mock` instead. It shows
simulated results and displays a Demo mode banner. Entering a URL on
`error.test` simulates a server error.

## Useful commands

| Command | What it does |
|---|---|
| `npm ci` | Installs the project's locked dependencies |
| `npm run dev` | Starts the development server |
| `npm run dev:mock` | Starts the demo version without the back end |
| `npm run build` | Builds the app into `dist/` for the back end to serve |

## What's included

- URL checks with clear results, confidence scores, and plain-language warnings
- Charts showing confidence, warning locations, and check history
- A local history of your checks, with an option to export it
- Responsive layouts and keyboard-accessible controls
- Helpful loading and error messages, including when the back end is offline
