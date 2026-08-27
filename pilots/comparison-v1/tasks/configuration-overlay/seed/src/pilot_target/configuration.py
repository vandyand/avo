def overlay_config(
    base: dict[str, object], override: dict[str, object]
) -> dict[str, object]:
    """Return an isolated recursive overlay of two configuration mappings.

    Mapping values merge recursively. A ``None`` override deletes that key.
    Every other override replaces the base value, including lists. Keys at all
    mapping levels must be strings. The result shares no mutable dictionary or
    list with either input, and neither input is mutated.
    """

    # Seeded defect: this is shallow, treats None as data, and aliases nested values.
    result = dict(base)
    result.update(override)
    return result
