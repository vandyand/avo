from reference_target import best_window


def test_single_window() -> None:
    assert best_window([1, 2, 3], 3) == (0, 6)


def test_invalid_width() -> None:
    try:
        best_window([1], 0)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid width must fail")
