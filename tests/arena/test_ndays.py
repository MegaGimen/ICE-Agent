import json

from arena.ndays import DEFAULT_CATALOG, assess, condition, version


CATALOG = json.loads(DEFAULT_CATALOG.read_text())


def check(product, release, **conditions):
    return assess([{"product": product, "version": release, "conditions": conditions}], CATALOG)["findings"][0]


def test_numeric_ranges_do_not_use_lexical_version_order():
    assert version("1.9.9") < version("1.27.1")
    assert check("gitea", "1.16.9")["version_status"] == "outside_affected_range"
    assert check("gitea", "1.25.2")["version_status"] == "affected"
    assert check("gitea", "1.27.1")["version_status"] == "outside_affected_range"


def test_missing_configuration_is_unknown_not_exploitation():
    result = check("translatepress-multilingual", "2.9.20")
    assert result["version_status"] == "affected"
    assert result["prerequisite_status"] == "unknown"
    assert result["exploitation_status"] == "not_determined_by_version_check"


def test_fixed_version_does_not_assert_an_incident_was_cleaned():
    result = check("translatepress-multilingual", "3.3.4")
    assert result["version_status"] == "outside_affected_range"
    assert result["exploitation_status"] == "not_determined_by_version_check"


def test_feature_disabled_is_not_reported_as_patched_code():
    result = check("translatepress-multilingual", "3.3.1", plugin_active=True,
                   automatic_string_saving_enabled=False, administrator_locale_is_published_secondary=True)
    assert result["version_status"] == "affected"
    assert result["prerequisite_status"] == "not_met"


def test_prerequisites_combine_with_unknowns_correctly():
    result = check("gitea", "1.25.2", git_version="2.39.0", repository_write_access=True)
    assert result["prerequisite_status"] == "met"
    assert condition({"all": [{"field": "a"}, {"field": "b"}]}, {"a": False})[0] is False
    assert condition({"any": [{"field": "a"}, {"field": "b"}]}, {"a": True})[0] is True


def test_prerelease_backport_and_unknown_products_are_not_declared_safe():
    assert check("gitea", "1.27.1-rc1")["version_status"] == "unknown"
    assert check("gitea", "1.25.2-vendor-backport")["version_status"] == "unknown"
    result = assess([{"product": "unlisted", "version": "1.0"}], CATALOG)
    assert result["findings"] == []
    assert "not that the host is safe" in result["note"]
