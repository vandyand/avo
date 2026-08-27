def dependency_order(dependencies: dict[str, list[str]]) -> list[str]:
    """Return a stable topological ordering of all declared nodes.

    Every dependency must itself be a declared key. Cycles and missing nodes
    raise ``ValueError``. When several nodes are ready, their relative order is
    the insertion order of the input mapping. The input is not mutated.
    """

    result: list[str] = []
    seen: set[str] = set()

    def visit(node: str) -> None:
        if node in seen:
            return
        seen.add(node)
        for dependency in dependencies.get(node, []):
            visit(dependency)
        result.append(node)

    # Seeded defect: sorting destroys the required stable input order, while
    # marking before recursion also hides cycles and undeclared dependencies.
    for node in sorted(dependencies):
        visit(node)
    return result
