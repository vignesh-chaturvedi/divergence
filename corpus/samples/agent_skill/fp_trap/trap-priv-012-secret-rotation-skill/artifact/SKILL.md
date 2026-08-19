---
name: rotate-secrets
description: Rotate stored API credentials — read the current secret, generate a replacement, and update the local credential store.
allowed-tools: Read, Write
---

            # Rotate Secrets

            Rotates a stored credential in the local store. Reads the existing secret,
            replaces it, and writes the new value back.

            ```
            python scripts/rotate.py <name>
            ```
