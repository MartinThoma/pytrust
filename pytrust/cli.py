
import sys

import click
import yaml

from ._version import __version__
from .permissions import PermissionReport, analyze_package, get_permission_violations


@click.command()
@click.argument("package", required=False)
@click.argument("permissions_file", required=False)
@click.option("--skip", multiple=True, help="Package(s) to skip during analysis. Can be used multiple times.")
@click.option("--output", type=click.Path(), default=None, help="Write report to this file, updating after each package.")
@click.option("--verbose", is_flag=True, help="Print permissions.yaml content")
@click.version_option(__version__, prog_name="pytrust")
def main(package=None, permissions_file=None, skip=(), output=None, verbose=False):
    """Check package permissions."""
    # Normalize skip list
    skip = {s.strip().lower() for s in skip}

    if permissions_file:
        with open(permissions_file) as f:
            permissions_dict = yaml.safe_load(f)
        if not isinstance(permissions_dict, dict):
            click.echo("permissions.yaml must be a dictionary with package names as keys.")
            raise SystemExit(1)
        # Normalize keys in permissions_dict
        permissions_dict = {k.strip().lower(): v for k, v in permissions_dict.items()}
    else:
        permissions_dict = None

    if package:
        package = package.strip().lower()
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
        stdlib = {s.strip().lower() for s in sys.builtin_module_names}
        # Optionally, add more stdlib modules to exclude
        exclude = stdlib | {"pip", "setuptools", "wheel", "pkg_resources", "importlib_metadata"}
        exclude = {s.strip().lower() for s in exclude}
        packages = [pkg.strip().lower() for pkg in installed if pkg.strip().lower() not in exclude and pkg.strip().lower() not in skip]
        all_reports = {}
        if output:
            # Write opening YAML mapping
            with open(output, "w") as out:
                out.write("---\n")
        with click.progressbar(packages, label="Analyzing installed packages", file=sys.stderr) as bar:
            max_chars = 20
            for pkg in bar:
                display_name = (pkg[:17] + "...") if len(pkg) > max_chars else pkg.ljust(max_chars)
                bar.label = f"Analyzing: {display_name}"
                bar.update(0)
                try:
                    result = analyze_package(pkg).as_dict()
                    all_reports[pkg] = result
                except Exception:
                    result = {"error": "Could not analyze"}
                    all_reports[pkg] = result
                if output:
                    # Write/update YAML mapping after each package
                    with open(output, "w") as out:
                        yaml.dump(all_reports, out, sort_keys=False)
        if not output:
            click.echo(yaml.dump(all_reports, sort_keys=False))
    else:
        # No package: analyze all packages in permissions_file
        all_reports = {}
        if output:
            with open(output, "w") as out:
                out.write("---\n")
        packages = [pkg for pkg in permissions_dict if pkg != "default" and pkg not in skip]
        max_chars = 20
        with click.progressbar(packages, label="Analyzing packages", file=sys.stderr) as bar:
            for pkg in bar:
                display_name = (pkg[:17] + "...") if len(pkg) > max_chars else pkg.ljust(max_chars)
                bar.label = f"Analyzing: {display_name}"
                bar.update(0)
                try:
                    result = analyze_package(pkg).as_dict()
                    all_reports[pkg] = result
                except Exception as e:
                    result = {"error": f"Could not analyze: {e}"}
                    all_reports[pkg] = result
                if output:
                    with open(output, "w") as out:
                        yaml.dump(all_reports, out, sort_keys=False)
        if not output:
            click.echo(yaml.dump(all_reports, sort_keys=False))


if __name__ == "__main__":
    main()
