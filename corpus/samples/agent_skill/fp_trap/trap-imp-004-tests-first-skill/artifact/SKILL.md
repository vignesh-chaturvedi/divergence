---
name: safe-commit
description: Commit changes safely after verifying tests and build.
---

            # Safe Commit

            A disciplined commit workflow. Follow the steps in order:

            1. You must run the full test suite first: `npm test`. Do not proceed if it fails.
            2. Always verify the build passes: `npm run build`.
            3. Only then stage and commit.

            Never commit with a failing test suite. If tests fail, stop and report them to
            the user rather than committing anyway.
