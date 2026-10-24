import pytest

from psatoolkit.core.authorization import (CONFIRMATION_PHRASE, NOTICE_SHA256, AuthorizationError, TargetScope,
                                           create_authorization, phrase_matches)


def _auth(**overrides):
    kwargs = dict(operator="Jane", organization="", engagement_reference="CHG-1", scope_statement="",
                  host="h", confirmed=True, method="gui")
    kwargs.update(overrides)
    return create_authorization(**kwargs)


def test_confirmed_authorization_record():
    rec = _auth()
    assert rec.operator == "Jane"
    assert rec.scope_statement == "Local host only"
    assert rec.notice_sha256 == NOTICE_SHA256
    assert rec.to_dict()["engagement_reference"] == "CHG-1"


@pytest.mark.parametrize("confirmed", [False, None, "yes", 1])
def test_authorization_requires_explicit_true(confirmed):
    with pytest.raises(AuthorizationError, match="not confirmed"):
        _auth(confirmed=confirmed)


@pytest.mark.parametrize("field", ["operator", "engagement_reference"])
def test_authorization_requires_operator_and_reference(field):
    with pytest.raises(AuthorizationError):
        _auth(**{field: "   "})


def test_authorization_rejects_unsafe_text():
    with pytest.raises(AuthorizationError):
        _auth(operator="Jane\n$(id)")


def test_phrase_matching():
    assert phrase_matches(CONFIRMATION_PHRASE)
    assert phrase_matches("  i am authorized ")
    for wrong in ("", "yes", "I AM AUTHORISED", "I AM AUTHORIZED!", None):
        assert not phrase_matches(wrong)


def test_scope_requires_confirmation_and_reference():
    scope = TargetScope()
    with pytest.raises(AuthorizationError, match="not confirmed"):
        scope.add("10.0.0.5", "REF-1", confirmed=False)
    with pytest.raises(AuthorizationError):
        scope.add("10.0.0.5", "", confirmed=True)
    assert scope.targets == []


def test_scope_membership_and_preview():
    scope = TargetScope()
    scope.add("10.0.0.0/30", "REF-1", True)
    scope.add("server.example.com", "REF-2", True)
    assert scope.total_hosts == 3
    assert scope.is_authorized("10.0.0.2")
    assert not scope.is_authorized("10.0.0.9")
    assert scope.is_authorized("SERVER.example.com")
    with pytest.raises(AuthorizationError, match="outside"):
        scope.require("8.8.8.8")
    preview = scope.preview([22, 443], rate_per_second=2)
    assert preview["total_connection_attempts"] == 6
    assert preview["estimated_minimum_duration_seconds"] == 3.0


def test_scope_limits_and_duplicates():
    scope = TargetScope(max_hosts_per_target=256, max_total_hosts=300)
    scope.add("10.0.0.0/24", "REF", True)
    with pytest.raises(AuthorizationError, match="already"):
        scope.add("10.0.0.0/24", "REF", True)
    with pytest.raises(AuthorizationError, match="total scope limit"):
        scope.add("10.0.1.0/24", "REF", True)
    with pytest.raises(AuthorizationError):
        scope.add("10.0.0.0/8", "REF", True)
    scope.remove("10.0.0.0/24")
    assert scope.total_hosts == 0
