import click
import yaml
from .permissions import analyze_package, get_permission_violations, PermissionReport



@click.command()
@click.argument("package")
@click.argument("permissions_file", required=False)
@click.option("--verbose", is_flag=True, help="Print permissions.yaml content")
def main(package, permissions_file=None, verbose=False):
    """Check package permissions."""

    report = analyze_package(package)

    if permissions_file:
        with open(permissions_file, "r") as f:
            permissions_dict = yaml.safe_load(f)
        if not isinstance(permissions_dict, dict):
            click.echo("permissions.yaml must be a dictionary with package names as keys.")
            raise SystemExit(1)

        pkg_perms = permissions_dict.get(package)

        if verbose:
            click.echo("Analysis result:")
            for k, v in report.as_dict().items():
                click.echo(f"{k}: {'Yes' if v else 'No'}")

        violations = get_permission_violations(
            required_permissions=report, given_permissions=PermissionReport(**pkg_perms)
        )

        if violations:
            click.echo("Permission violations found:")
            for key, required, given in violations:
                click.echo(f" - {key}: REQUIRED but NOT GIVEN")
        else:
            click.echo("No permission violations found.")
            raise SystemExit(1)
    else:
        # No permissions_file: print valid YAML permission report
        click.echo(yaml.dump({package: report.as_dict()}, sort_keys=False))


if __name__ == "__main__":
    main()
