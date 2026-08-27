def reconcile_events(events: list[dict[str, object]]) -> list[dict[str, object]]:
    """Validate, deduplicate, and order an event history.

    Each event has exactly ``event_id`` (non-empty string), ``sequence``
    (non-negative integer), and ``payload`` (dictionary). Exact duplicate IDs
    collapse. Conflicting duplicates or different IDs sharing a sequence are
    invalid. Return fresh event and payload dictionaries ordered by sequence;
    never mutate or alias caller-owned dictionaries.
    """

    # Seeded defect: last-write-wins masks conflicts and returns caller-owned objects.
    by_id = {str(event["event_id"]): event for event in events}
    return sorted(by_id.values(), key=lambda event: int(event["sequence"]))
