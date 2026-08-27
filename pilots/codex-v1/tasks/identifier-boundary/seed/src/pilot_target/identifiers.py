def canonical_identifier(value: str) -> str:
    """Normalize a non-empty relative identifier to slash-separated components.

    Both slash styles are separators. Empty and "." components are removed.
    Absolute paths, drive-qualified paths, and any ".." component are invalid.
    """

    parts = [
        part
        for part in value.replace("\\", "/").split("/")
        if part not in {"", ".", ".."}
    ]
    return "/".join(parts)

