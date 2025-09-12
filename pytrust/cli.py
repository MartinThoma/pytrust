import sys

import click
import yaml

from .permissions import PermissionReport, analyze_package, get_permission_violations


@click.command()
@click.argument("package", required=False)
@click.argument("permissions_file", required=False)
@click.option("--verbose", is_flag=True, help="Print permissions.yaml content")
def main(package=None, permissions_file=None, verbose=False):
    """Check package permissions."""
    if permissions_file:
        with open(permissions_file) as f:
            permissions_dict = yaml.safe_load(f)
        if not isinstance(permissions_dict, dict):
            click.echo("permissions.yaml must be a dictionary with package names as keys.")
            raise SystemExit(1)
    else:
        permissions_dict = None

    if package:
        report = analyze_package(package)
        if permissions_dict:
            pkg_perms = permissions_dict.get(package)
            if verbose:
                click.echo("Analysis result:")
                for k, v in report.as_dict().items():
                    click.echo(f"{k}: {'Yes' if v else 'No'}")
            violations = get_permission_violations(
                required_permissions=report, given_permissions=PermissionReport(**pkg_perms),
            )
            if violations:
                click.echo("Permission violations found:")
                for key, _required, _given in violations:
                    click.echo(f" - {key}: REQUIRED but NOT GIVEN")
            else:
                click.echo("No permission violations found.")
                raise SystemExit(1)
        else:
            # No permissions_file: print valid YAML permission report
            click.echo(yaml.dump({package: report.as_dict()}, sort_keys=False))
    # No package and no permissions_file: analyze all installed non-default packages
    elif not permissions_dict:
        try:
            # Use importlib.metadata for Python >=3.8
            try:
                from importlib.metadata import distributions
            except ImportError:
                from importlib_metadata import distributions
            installed = set()
            for dist in distributions():
                name = dist.metadata["Name"]
                if name:
                    installed.add(name)
        except Exception as e:
            click.echo("Could not list installed packages.")
            raise SystemExit(1) from e

        # Filter out default/builtin packages
        stdlib = set(sys.builtin_module_names)
        # Optionally, add more stdlib modules to exclude
        exclude = stdlib | {"pip", "setuptools", "wheel", "pkg_resources", "importlib_metadata"}
        packages = [pkg for pkg in installed if pkg not in exclude]
        all_reports = {}
        with click.progressbar(packages, label="Analyzing installed packages") as bar:
            for pkg in bar:
                try:
                    all_reports[pkg] = analyze_package(pkg).as_dict()
                except Exception:
                    all_reports[pkg] = {"error": "Could not analyze"}
        click.echo(yaml.dump(all_reports, sort_keys=False))
    else:
        # No package: analyze all packages in permissions_file
        all_reports = {}
        packages = [pkg for pkg in permissions_dict if pkg != "default"]
        with click.progressbar(packages, label="Analyzing packages") as bar:
            for pkg in bar:
                all_reports[pkg] = analyze_package(pkg).as_dict()
        click.echo(yaml.dump(all_reports, sort_keys=False))


if __name__ == "__main__":
    main()
