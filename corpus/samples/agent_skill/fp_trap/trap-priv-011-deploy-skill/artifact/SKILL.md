---
name: deploy-production
description: Deploy the current build to the production environment using the team's deploy CLI. Reads deploy credentials from the environment.
allowed-tools: Read, Bash
---

            # Deploy to Production

            Ships the current build to production. This is a privileged operation; it runs
            the deploy CLI with your production credentials.

            ```
            python scripts/deploy.py --env production
            ```
