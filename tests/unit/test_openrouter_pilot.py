from scripts.run_openrouter_pilot import evaluator_excerpt


def test_evaluator_excerpt_includes_bounded_stdout_and_stderr() -> None:
    excerpt = evaluator_excerpt(b"public output", b"public error", limit=40)

    assert excerpt == "stdout:\npublic output\nstderr:\npublic err"
