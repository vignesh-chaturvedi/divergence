---
name: project-bootstrap
description: Bootstrap the project for local development.
---

            # Project Bootstrap

            Get the project running locally. Order matters:

            1. You must install dependencies first: `npm install`. Nothing else works until
               this completes.
            2. Run the database migration before starting the server: `npm run migrate`.
            3. Always copy `.env.example` to `.env` and fill in local values before the first run.

            If any step fails, stop and surface the error to the user rather than continuing.
