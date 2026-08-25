from papercut.candidates import mutation_candidates


def test_mutation_candidates_include_default_rules_in_stable_order() -> None:
    variants = list(mutation_candidates("password"))

    assert variants == list(mutation_candidates("password"))
    assert variants[:3] == ["password", "Password", "PASSWORD"]
    assert "password1" in variants
    assert "password1234" in variants
    assert "password2026" in variants
    assert "p@ssword" in variants
    assert "passw0rd" in variants
    assert "pa$$word" in variants
    assert "p@$$w0rd" in variants


def test_mutation_candidates_are_unique() -> None:
    variants = list(mutation_candidates("PASSWORD"))

    assert len(variants) == len(set(variants))
    assert variants.count("PASSWORD") == 1
