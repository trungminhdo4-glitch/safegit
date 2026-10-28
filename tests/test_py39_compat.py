"""Python 3.9 compatibility guard that also runs on newer interpreters.

`from __future__ import annotations` only defers annotations.  A module-level
alias such as ``Action = A | B`` is evaluated at import time and raises
``TypeError`` on Python 3.9 (CI matrix), while passing silently on 3.10+.
"""

from __future__ import annotations

import ast
import pathlib
import unittest

SRC = pathlib.Path(__file__).resolve().parents[1] / "src"


BUILTIN_TYPES = {"str", "int", "float", "bool", "bytes", "list", "dict", "tuple", "set", "frozenset", "type", "object"}


def _is_type_name(node: ast.AST) -> bool:
    # CamelCase classes, builtin types, None and generics; ALL_CAPS flags (READ | WRITE) are not types.
    if isinstance(node, ast.Name):
        return node.id in BUILTIN_TYPES or (node.id[:1].isupper() and not (len(node.id) > 1 and node.id.isupper()))
    if isinstance(node, ast.Subscript):
        return _is_type_name(node.value)
    return isinstance(node, ast.Constant) and node.value is None


def _is_type_union(node: ast.AST) -> bool:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return all(_is_type_union(n) or _is_type_name(n) for n in (node.left, node.right))
    return False


class Py39CompatTests(unittest.TestCase):
    def test_sources_parse_with_python39_grammar(self):
        for path in SRC.rglob("*.py"):
            with self.subTest(path=path.name):
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 9))

    def test_no_runtime_pep604_unions(self):
        offenders = []
        for path in SRC.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                value = None
                if isinstance(node, ast.Assign):
                    value = node.value
                elif isinstance(node, ast.Call) and getattr(node.func, "id", None) in {"isinstance", "issubclass"} and len(node.args) == 2:
                    value = node.args[1]
                if value is not None and _is_type_union(value):
                    offenders.append(f"{path.relative_to(SRC)}:{node.lineno}")
        self.assertEqual(offenders, [], "use typing.Union for runtime type expressions (Python 3.9)")


if __name__ == "__main__":
    unittest.main()
