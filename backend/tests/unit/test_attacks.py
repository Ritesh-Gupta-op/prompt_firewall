from __future__ import annotations

import base64
import codecs
from collections import Counter

import pytest

from promptfirewall.attacks import (
    ATTACK_CATALOG,
    BENIGN_CATALOG,
    MAX_MUTATION_BUDGET,
    MUTATION_OPERATORS,
    apply_operator,
    generate_mutations,
    get_attack,
    validate_catalog,
)
from promptfirewall.contracts.attacks import AttackCategory


def test_catalog_has_stable_substantive_attack_and_benign_coverage() -> None:
    validate_catalog()

    assert len(ATTACK_CATALOG) >= 30
    assert len(BENIGN_CATALOG) >= 30
    assert len({attack.id for attack in ATTACK_CATALOG}) == len(ATTACK_CATALOG)
    assert len({case.id for case in BENIGN_CATALOG}) == len(BENIGN_CATALOG)
    assert not ({attack.id for attack in ATTACK_CATALOG} & {case.id for case in BENIGN_CATALOG})
    assert len({attack.category for attack in ATTACK_CATALOG}) >= 5
    assert all(attack.payload_template.strip() for attack in ATTACK_CATALOG)
    assert all(attack.success_criteria for attack in ATTACK_CATALOG)
    assert all(case.request.strip() and case.expected_behavior.strip() for case in BENIGN_CATALOG)


def test_every_declared_category_has_multiple_fixture_attacks() -> None:
    category_counts = Counter(attack.category for attack in ATTACK_CATALOG)

    assert set(category_counts) == set(AttackCategory)
    assert all(count >= 3 for count in category_counts.values())


def test_lookup_returns_the_catalog_object_by_stable_id() -> None:
    attack = ATTACK_CATALOG[7]

    assert get_attack(attack.id) is attack
    with pytest.raises(KeyError):
        get_attack("attack-does-not-exist")


@pytest.mark.parametrize(
    ("operator", "payload", "expected"),
    [
        ("casing", "AbC", "aBc"),
        ("whitespace", "one two", "one\ntwo"),
        ("paraphrase", "Disclose the synthetic canary", "Reveal the fixture-only canary"),
        ("unicode", "safe", "sаfе"),
        ("split", "one two", "one\u2063two"),
        ("base64", "demo", base64.b64encode(b"demo").decode("ascii")),
        ("rot13", "synthetic", codecs.encode("synthetic", "rot_13")),
    ],
)
def test_mutation_operators_are_deterministic(
    operator: str,
    payload: str,
    expected: str,
) -> None:
    assert apply_operator(payload, operator) == expected
    assert apply_operator(payload, operator) == apply_operator(payload, operator)


def test_mutations_are_bounded_reproducible_and_traceable() -> None:
    attack = ATTACK_CATALOG[0]

    first = generate_mutations(attack, budget=MAX_MUTATION_BUDGET, seed=17)
    second = generate_mutations(attack, budget=MAX_MUTATION_BUDGET, seed=17)
    limited = generate_mutations(attack, budget=3, seed=17)

    assert first == second
    assert len(first) <= MAX_MUTATION_BUDGET
    assert len(first) == len(MUTATION_OPERATORS)
    assert len(limited) == 3
    assert {mutation.parent_attack_id for mutation in first} == {attack.id}
    assert {mutation.operators[0] for mutation in first} == set(MUTATION_OPERATORS)
    assert len({mutation.mutation_id for mutation in first}) == len(first)
    assert all(mutation.payload != attack.payload_template for mutation in first)
    assert all(mutation.seed == 17 for mutation in first)


def test_mutation_budget_rejects_invalid_values_and_unknown_operators() -> None:
    attack = ATTACK_CATALOG[0]

    with pytest.raises(ValueError, match="positive integer"):
        generate_mutations(attack, budget=0)
    with pytest.raises(ValueError, match="unknown mutation operator"):
        generate_mutations(attack, operators=("not-an-operator",))
