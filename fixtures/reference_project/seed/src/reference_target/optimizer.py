def best_window(values: list[int], width: int) -> tuple[int, int]:
    """Return the start index and sum of the highest-scoring fixed-width window."""
    if width <= 0 or width > len(values):
        raise ValueError("width must select at least one available value")
    # Seeded defect: this inspects only the first window.
    return 0, sum(values[:width])
