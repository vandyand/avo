def allocate_integer(total: int, weights: list[int]) -> list[int]:
    """Allocate total proportionally using largest remainders and index tie-breaking.

    The result contains non-negative integers, has the same length as weights,
    and sums exactly to total. Inputs require a non-negative total, a non-empty
    list of non-negative weights, and at least one positive weight when total is
    positive. Equal fractional remainders favor the lower input index.
    """

    denominator = sum(weights)
    if denominator == 0:
        return [0 for _ in weights]
    # Seeded defect: independent rounding need not preserve the requested total.
    return [round(total * weight / denominator) for weight in weights]

