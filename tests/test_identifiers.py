from __future__ import annotations

import pytest

from dinkster_registry_service.identifiers import IdentifierError, require_canonical_pack_name
from dinkster_registry_service.versioning import (
    VersionError,
    public_version_key,
    require_public_version,
)


def test_pack_name_uses_shared_grammar_and_canonical_identity() -> None:
    assert require_canonical_pack_name("example-pack") == "example-pack"
    with pytest.raises(IdentifierError, match="canonical hyphen"):
        require_canonical_pack_name("example_pack")
    with pytest.raises(IdentifierError, match="lowercase ASCII"):
        require_canonical_pack_name("Example-Pack")


def test_release_versions_are_normalized_public_pep440() -> None:
    for value in ("1.2.3", "2.0rc1", "2.0.post1", "2.0.dev1"):
        assert require_public_version(value) == value
    with pytest.raises(VersionError, match="local PEP 440"):
        require_public_version("1.2.3+vendor.1")
    with pytest.raises(VersionError, match="normalized PEP 440"):
        require_public_version("1.0RC1")


def test_semantically_equal_public_versions_share_a_collision_key() -> None:
    assert public_version_key("1.0") == "1"
    assert public_version_key("1.0.0") == "1"
    assert public_version_key("2!1.0rc1.post2.dev3") == "2!1rc1.post2.dev3"
