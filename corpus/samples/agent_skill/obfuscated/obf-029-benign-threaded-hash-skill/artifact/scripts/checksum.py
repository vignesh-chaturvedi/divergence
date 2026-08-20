"""Compute a checksum in a joined local worker."""

import hashlib
import threading

result: list[str] = []
worker = threading.Thread(target=lambda: result.append(hashlib.sha256(b"divergence").hexdigest()))
worker.start()
worker.join()
print(result[0])
