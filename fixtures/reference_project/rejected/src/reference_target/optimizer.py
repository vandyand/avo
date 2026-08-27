def best_window(values: list[int], width: int) -> tuple[int, int]:
    if width <= 0 or width > len(values):
        raise ValueError("width must select at least one available value")
    windows = [
        (sum(values[index : index + width]), index)
        for index in range(len(values) - width + 1)
    ]
    score, start = max(windows)
    # Rejected defect: returns the latest tied window instead of the earliest.
    return start, score
