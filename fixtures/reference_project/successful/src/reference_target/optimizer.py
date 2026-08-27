def best_window(values: list[int], width: int) -> tuple[int, int]:
    """Return the earliest start index and sum of the best fixed-width window."""
    if width <= 0 or width > len(values):
        raise ValueError("width must select at least one available value")
    current = sum(values[:width])
    best_sum = current
    best_start = 0
    for start in range(1, len(values) - width + 1):
        current += values[start + width - 1] - values[start - 1]
        if current > best_sum:
            best_sum = current
            best_start = start
    return best_start, best_sum
