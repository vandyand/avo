def retry_delays(base_ms: int, factor: int, attempts: int, cap_ms: int) -> list[int]:
    """Return one delay per attempt using capped integer exponential backoff.

    The first delay is ``min(base_ms, cap_ms)`` and each later uncapped delay
    multiplies the base by another power of ``factor``. All inputs are integers.
    ``base_ms``, ``attempts``, and ``cap_ms`` must be non-negative; ``factor``
    must be at least one.
    """

    if base_ms < 0 or attempts < 0 or cap_ms < 0 or factor < 1:
        raise ValueError("invalid retry schedule")
    # Seeded defect: the sequence starts at factor**1 instead of factor**0.
    return [min(base_ms * factor**attempt, cap_ms) for attempt in range(1, attempts + 1)]
