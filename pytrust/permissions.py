"""
Permissions analysis logic for pytrust CLI.
"""

import ast
import importlib
import os


class PermissionReport:
    def __init__(
        self, file_system=False, env_vars=False, web_requests=False, exec_usage=False,
    ):
        self.file_system = file_system
        self.env_vars = env_vars
        self.web_requests = web_requests
        self.exec_usage = exec_usage

    def as_dict(self):
        return {
            "file_system": self.file_system,
            "env_vars": self.env_vars,
            "web_requests": self.web_requests,
            "exec_usage": self.exec_usage,
        }


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
                # File system
                if isinstance(node, ast.Import):
                    for n in node.names:
                        if n.name in ["os", "shutil", "pathlib"]:
                            report.file_system = True
                        if n.name in ["requests", "http", "urllib", "aiohttp"]:
                            report.web_requests = True
                if isinstance(node, ast.ImportFrom):
                    if node.module in ["os", "shutil", "pathlib"]:
                        report.file_system = True
                    if node.module in ["requests", "http", "urllib", "aiohttp"]:
                        report.web_requests = True
                # Env vars
                if isinstance(node, ast.Attribute) and getattr(node, "attr", None) == "environ":
                        report.env_vars = True
                # Exec usage
                if isinstance(node, ast.Call):
                    # Detect 'open' usage for file system
                    if isinstance(node.func, ast.Name) and node.func.id == "open":
                        report.file_system = True
                    # Detect exec/eval usage
                    if isinstance(node.func, ast.Name) and node.func.id in [
                        "exec",
                        "eval",
                    ]:
                        report.exec_usage = True
                    # Detect os.system, os.popen, os.spawn
                    if isinstance(node.func, ast.Attribute) and node.func.attr in [
                        "system",
                        "popen",
                        "spawn",
                    ]:
                        report.exec_usage = True
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
