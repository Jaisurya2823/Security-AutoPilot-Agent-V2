from src.manifest_parser import parse_package_json, parse_requirements_txt


def test_parse_requirements_pinned_versions():
    content = """
    # a comment
    requests==2.31.0
    numpy==1.26.4  # inline comment
    """
    resolved, unresolved = parse_requirements_txt(content)
    assert [(p.name, p.version) for p in resolved] == [("requests", "2.31.0"), ("numpy", "1.26.4")]
    assert unresolved == []


def test_parse_requirements_unpinned_and_ranges_are_unresolved():
    content = "flask\ndjango>=4.0\nurllib3~=2.0\n"
    resolved, unresolved = parse_requirements_txt(content)
    assert resolved == []
    assert len(unresolved) == 3


def test_parse_requirements_skips_options_and_vcs():
    content = "-r base.txt\n--index-url https://example.com/simple\ngit+https://github.com/x/y.git\nrequests==2.31.0\n"
    resolved, unresolved = parse_requirements_txt(content)
    assert [(p.name, p.version) for p in resolved] == [("requests", "2.31.0")]
    assert any("git+" in u for u in unresolved)


def test_parse_requirements_with_extras():
    resolved, _ = parse_requirements_txt("requests[security]==2.31.0\n")
    assert resolved[0].name == "requests"
    assert resolved[0].version == "2.31.0"


def test_parse_package_json_exact_versions_resolved():
    content = """
    {
      "dependencies": {"lodash": "4.17.21", "express": "^4.18.0"},
      "devDependencies": {"jest": "29.7.0"}
    }
    """
    resolved, unresolved, scripts = parse_package_json(content)
    resolved_names = {p.name: p.version for p in resolved}
    assert resolved_names == {"lodash": "4.17.21", "jest": "29.7.0"}
    assert unresolved == ["express@^4.18.0"]
    assert scripts == []


def test_parse_package_json_flags_lifecycle_scripts():
    content = """
    {
      "dependencies": {"lodash": "4.17.21"},
      "scripts": {"postinstall": "node scripts/setup.js", "test": "jest"}
    }
    """
    _, _, scripts = parse_package_json(content)
    assert scripts == ["postinstall: node scripts/setup.js"]


def test_parse_package_json_invalid_json_raises():
    import pytest
    with pytest.raises(ValueError, match="not valid JSON"):
        parse_package_json("{not json")
