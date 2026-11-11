from scoring import assign_tier


def test_kev_is_always_tier_1():
    # Known exploitation beats every score, even very low ones.
    assert assign_tier(in_kev=True, epss=0.001, cvss=2.0) == 1


def test_high_epss_is_tier_2():
    assert assign_tier(in_kev=False, epss=0.45, cvss=5.0) == 2


def test_epss_exactly_at_threshold_counts():
    assert assign_tier(in_kev=False, epss=0.10, cvss=5.0) == 2


def test_critical_cvss_with_low_epss_is_only_tier_3():
    # The case the whole project is basically about: scary score, little real world risk.
    assert assign_tier(in_kev=False, epss=0.002, cvss=9.8) == 3


def test_low_scores_are_tier_4():
    assert assign_tier(in_kev=False, epss=0.002, cvss=5.3) == 4


def test_missing_scores_do_not_crash():
    assert assign_tier(in_kev=False, epss=None, cvss=None) == 4
    assert assign_tier(in_kev=False, epss=None, cvss=9.8) == 3


def test_custom_threshold():
    assert assign_tier(in_kev=False, epss=0.05, cvss=5.0, epss_threshold=0.01) == 2