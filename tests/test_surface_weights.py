"""Tests for tools/surface_weights.py.

Discipline:
    - Tests assert on weight ranges and ordering, NOT on exact float values.
    - This keeps the table tunable without breaking the test suite.
    - Pattern names are checked via `weight_label()` rather than coupling
      to internal regex strings.
"""

from surface_weights import MAX_WEIGHT, value_weight, weight_label


class TestValueWeightBasics:

    def test_empty_path_returns_neutral(self):
        assert value_weight("") == 1.0

    def test_unmatched_path_returns_neutral(self):
        assert value_weight("/some/random/path/no/keywords") == 1.0
        assert weight_label("/some/random/path/no/keywords") == ""

    def test_weight_is_capped(self):
        # admin × billing × auth × api_v stacks deep; must cap at MAX_WEIGHT
        path = "/api/v2/admin/billing/oauth/token"
        assert value_weight(path) == MAX_WEIGHT


class TestHighValuePatterns:

    def test_admin_amplifies(self):
        assert value_weight("/admin/users") >= 5.0
        assert "admin" in weight_label("/admin/users")

    def test_billing_amplifies(self):
        assert value_weight("/billing/invoices") >= 5.0
        assert "billing" in weight_label("/billing/invoices")

    def test_payout_amplifies(self):
        assert value_weight("/payout/account/123") >= 5.0

    def test_webhook_amplifies(self):
        assert value_weight("/webhook/stripe") >= 4.0
        assert "webhook" in weight_label("/webhook/stripe")

    def test_auth_amplifies(self):
        # Must hit /auth as own segment but not random "author"
        assert value_weight("/auth/callback") >= 4.0
        assert value_weight("/oauth/authorize") >= 4.0

    def test_tenant_amplifies(self):
        assert value_weight("/tenants/abc123/users") >= 3.0
        assert value_weight("/workspaces/xyz") >= 3.0

    def test_upload_amplifies(self):
        assert value_weight("/upload/avatar") >= 3.5
        assert value_weight("/export/csv") >= 3.5

    def test_api_versioned_path_amplifies(self):
        assert value_weight("/api/v2/orders") >= 2.0
        assert value_weight("/api/v10/anything") >= 2.0

    def test_graphql_amplifies(self):
        assert value_weight("/graphql") >= 2.5


class TestLowValuePatterns:

    def test_blog_deprioritized(self):
        assert value_weight("/blog/post-1") < 1.0
        assert "low" in weight_label("/blog/post-1")

    def test_bare_numeric_route_deprioritized(self):
        assert value_weight("/16") < 1.0
        assert "bare-numeric" in weight_label("/16")
        assert value_weight("/orders/16") == 1.0

    def test_marketing_deprioritized(self):
        assert value_weight("/marketing/campaign") < 1.0

    def test_docs_deprioritized_but_api_docs_excluded(self):
        # /docs alone -> low. /docs/api/* preserved at neutral.
        assert value_weight("/docs/getting-started") < 1.0
        assert value_weight("/docs/api/v1") == 1.0


class TestOrderingInvariants:
    """High-value paths must outrank low-value paths in the weight space."""

    def test_admin_beats_blog(self):
        assert value_weight("/admin/billing") > value_weight("/blog/post")

    def test_webhook_beats_static(self):
        assert value_weight("/webhook/stripe") > value_weight("/static/foo.js")

    def test_api_v_beats_marketing(self):
        assert value_weight("/api/v2/users") > value_weight("/marketing/x")

    def test_oauth_beats_docs(self):
        assert value_weight("/oauth/token") > value_weight("/docs/intro")


class TestCompositeWeights:

    def test_multiple_high_value_segments_stack(self):
        # /admin and /billing both hit; weight should be > either alone
        admin_only = value_weight("/admin/random")
        billing_only = value_weight("/billing/random")
        both = value_weight("/admin/billing/random")
        assert both > admin_only
        assert both > billing_only
        # capped at MAX_WEIGHT
        assert both <= MAX_WEIGHT

    def test_label_records_multiple_classes(self):
        label = weight_label("/admin/billing/random")
        assert "admin" in label
        assert "billing" in label


class TestWeightLabelEdgeCases:

    def test_empty_path_label(self):
        assert weight_label("") == ""

    def test_neutral_path_label(self):
        assert weight_label("/something/uncategorized") == ""

    def test_label_format_compact(self):
        # Format: "value-class: <class1>+<class2>+..."
        label = weight_label("/admin/webhook/oauth")
        assert label.startswith("value-class:")
