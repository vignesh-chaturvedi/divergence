"""The deterministic core: acquisition, declared-interface analysis, and the ledger.

Nothing in this package performs inference. Every finding it emits is the result of
parsing or set algebra, which is what makes it free to run and reproducible by
construction.
"""
