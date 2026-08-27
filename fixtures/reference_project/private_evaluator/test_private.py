from reference_target import best_window


def test_later_window_can_win() -> None:
    assert best_window([-4, 1, 8, 2], 2) == (2, 10)


def test_ties_choose_earliest_window() -> None:
    assert best_window([2, 2, 2], 2) == (0, 4)


def test_negative_values() -> None:
    assert best_window([-9, -4, -7], 1) == (1, -4)
