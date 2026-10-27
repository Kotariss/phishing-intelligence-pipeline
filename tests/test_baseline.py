"""Interpretable baseline (ТЗ 4.1.3.2): features, tree, explanation path."""
import json

from baseline import FEATURES, DecisionTree, extract_features, features_from_html

PHISH = '<html><title>Login</title><body><form action="https://evil.example/p"><input type="password"></form>' \
        '<script src="https://cdn.evil.example/a.js"></script></body></html>'
PLAIN = "<html><title>About the company</title><body><p>Hello</p></body></html>"


def test_features_are_raw_structural_counts():
    f = features_from_html(PHISH)
    assert set(f) == set(FEATURES)
    assert f["has_password_field"] == 1.0 and f["forms_count"] == 1.0 and f["external_scripts"] >= 1.0
    assert features_from_html(PLAIN)["forms_count"] == 0.0


def test_tree_separates_toy_data_and_reports_importance_and_path():
    names = ["a", "b"]
    rows = [[1.0, 0.0]] * 30 + [[0.0, 0.0]] * 30 + [[1.0, 1.0]] * 5
    labels = [1] * 30 + [0] * 30 + [1] * 5
    tree = DecisionTree(max_depth=2, min_leaf=5).fit(rows, labels, names)
    assert tree.importance and next(iter(tree.importance)) == "a"
    prob, path = DecisionTree.predict_proba_nodes(tree.nodes, {"a": 1.0, "b": 0.0})
    assert prob > 0.5 and path and "a" in path[0]
    assert DecisionTree.predict_proba_nodes(tree.nodes, {"a": 0.0, "b": 0.0})[0] < 0.5


def test_saved_model_is_valid_json_with_version():
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "models", "baseline_v1.json")
    if not os.path.isfile(path):
        return
    model = json.load(open(path, encoding="utf-8"))
    assert model["version"].startswith("baseline-tree-") and model["tree"] and model["feature_importance"]
