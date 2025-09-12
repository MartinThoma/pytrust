"""
Permissions analysis logic for pytrust CLI.
"""

import ast
import importlib
import os


class Permission:
    def __init__(self, name, is_used):
        self.name = name
        self.is_used = is_used


PERMISSIONS = [
    Permission(
        "file_system",
        lambda node: (
            (isinstance(node, ast.Import) and any(n.name in ["os", "shutil", "pathlib"] for n in node.names))
            or (isinstance(node, ast.ImportFrom) and node.module in ["os", "shutil", "pathlib"])
            or (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open")
        ),
    ),
    Permission(
        "env_vars",
        lambda node: isinstance(node, ast.Attribute) and getattr(node, "attr", None) == "environ",
    ),
    Permission(
        "web_requests",
        lambda node: (
            (isinstance(node, ast.Import) and any(n.name in ["requests", "http", "urllib", "aiohttp"] for n in node.names))
            or (isinstance(node, ast.ImportFrom) and node.module in ["requests", "http", "urllib", "aiohttp"])
        ),
    ),
    Permission(
        "exec_usage",
        lambda node: (
            (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ["exec", "eval"])
            or (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ["system", "popen", "spawn"])
        ),
    ),
]


class PermissionReport:
    def __init__(self):
        self.used = {perm.name: False for perm in PERMISSIONS}

    def mark_used(self, perm_name):
        self.used[perm_name] = True

    def as_dict(self):
        return {k: True for k, v in self.used.items() if v}


def analyze_package(package_name: str) -> PermissionReport:
    report = PermissionReport()
    try:
        module = importlib.import_module(package_name)
    except Exception:
        return report
    # Find source files
    files = []
    if hasattr(module, "__file__"):
        files.append(module.__file__)
    if hasattr(module, "__path__"):
        for path in module.__path__:
            for root, _, filenames in os.walk(path):
                for fname in filenames:
                    if fname.endswith(".py"):
                        files.append(os.path.join(root, fname))
    # Analyze AST for permissions
    for file in files:
        try:
            with open(file, encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=file)
            for node in ast.walk(tree):
                for perm in PERMISSIONS:
                    if perm.is_used(node):
                        report.mark_used(perm.name)
        except Exception:
            continue
    return report


def get_permission_violations(
    required_permissions: PermissionReport, given_permissions: PermissionReport,
):
    violations = []
    for key, required in required_permissions.as_dict().items():
        given = given_permissions.as_dict().get(key, False)
        if required and not given:
            violations.append((key, required, given))
    return violations
