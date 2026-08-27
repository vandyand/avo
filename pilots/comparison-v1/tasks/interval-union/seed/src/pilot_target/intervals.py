def union_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Return the canonical union of half-open integer intervals.

    Inputs may be unsorted. Intervals with equal endpoints are empty and are
    omitted. Overlapping or touching intervals coalesce. An interval whose end
    is less than its start is invalid. The input list is not mutated.
    """

    merged: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        if end < start:
            raise ValueError("interval end precedes start")
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged
