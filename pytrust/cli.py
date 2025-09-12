import click
import yaml
from .permissions import analyze_package

@click.command()
@click.argument('package')
@click.argument('permissions_file')
@click.option('--verbose', is_flag=True, help='Print permissions.yaml content')
def main(package, permissions_file, verbose):
	"""Check package permissions."""
	report = analyze_package(package)
	click.echo("Analysis result:")
	for k, v in report.as_dict().items():
		click.echo(f"{k}: {'Yes' if v else 'No'}")

	try:
		with open(permissions_file, "r") as f:
			permissions_dict = yaml.safe_load(f)
		if not isinstance(permissions_dict, dict):
			click.echo("permissions.yaml must be a dictionary with package names as keys.")
			raise SystemExit(1)
		pkg_perms = permissions_dict.get(package)
		if pkg_perms is None:
			click.echo(f"No permissions specified for package '{package}' in permissions.yaml.")
			raise SystemExit(1)
		actual = report.as_dict()
		missing = False
		if verbose:
			click.echo(f"\nRequired permissions for '{package}':")
			for key, value in pkg_perms.items():
				click.echo(f"{key}: {value}")
		click.echo("\nPermission comparison:")
		for key in actual:
			required = pkg_perms.get(key)
			if required is None:
				continue
			if required and not actual[key]:
				click.echo(f"{key}: REQUIRED but NOT GIVEN (required={required}, actual={actual[key]})")
				missing = True
			elif actual[key] == required:
				click.echo(f"{key}: OK (required={required}, actual={actual[key]})")
			else:
				# Only print mismatches if permission is required
				if required:
					click.echo(f"{key}: MISMATCH (required={required}, actual={actual[key]})")
					missing = True
		if missing:
			raise SystemExit(1)
	except Exception as e:
		click.echo(f"Could not read permissions file: {e}")
		raise SystemExit(1)

if __name__ == "__main__":
	main()
