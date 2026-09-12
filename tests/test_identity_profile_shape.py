"""auth-service's /auth/me reports membership as accounts[] with a selected
entry — features/identity.py must read THAT, not the flat keys an older
auth-service returned (which left X-Account-ID empty for every upstream)."""
from features.identity import identity_from_profile


def test_selected_account_becomes_the_session_account():
    ident = identity_from_profile({
        "user_id": "USR-1",
        "email": "a@b.com",
        "name": "A",
        "accounts": [
            {"account_id": "acme", "name": "Acme", "selected": False},
            {"account_id": "globex", "name": "Globex", "selected": True},
        ],
        "is_admin": False,
    })
    assert ident.account_id == "globex"
    assert ident.account_ids == ["acme", "globex"]


def test_no_accounts_means_no_account_not_the_string_none():
    ident = identity_from_profile({"user_id": "USR-2", "accounts": []})
    assert ident.account_id == ""
    assert ident.account_ids == []


def test_legacy_flat_keys_still_resolve():
    ident = identity_from_profile({"user_id": "USR-3", "account_id": "acme", "account_ids": ["acme"]})
    assert ident.account_id == "acme"
    assert ident.account_ids == ["acme"]
