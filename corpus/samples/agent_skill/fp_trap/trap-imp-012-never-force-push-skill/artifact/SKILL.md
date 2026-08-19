---
name: git-hygiene
description: Keep git history clean and safe when working on shared branches.
---

            # Git Hygiene

            Rules for working safely on shared branches:

            - Never force-push to `main` or any shared branch. If a rebase requires it, stop
              and ask the user.
            - Do not rewrite history that has already been pushed and pulled by others.
            - Never delete a branch without confirming it is merged.
            - Always prefer a merge commit on shared branches over a force-push.

            When any of these would be violated, halt and explain the risk to the user
            rather than proceeding.
