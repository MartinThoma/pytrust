# pytrust

![PyPI](https://img.shields.io/pypi/v/pytrust?color=blue)
![License](https://img.shields.io/github/license/MartinThoma/pytrust)

**pytrust** is a CLI tool to analyze Python packages for their use of file system, environment variables, web requests, and exec calls. It helps you audit dependencies and generate permission reports in YAML format.


## Installation

```bash
pip install pytrust
```


## Usage

### Analyze a single package and print its permissions as YAML
```bash
$ pytrust pypdf
pypdf:
  file_system: true
  env_vars: false
  web_requests: false
  exec_usage: false

```

### Check a package against a permissions file
```bash
$ pytrust pypdf package-permissions.yaml
Permission violations found:
 - file_system: REQUIRED but NOT GIVEN
```



### Analyze all installed (non-default) packages and print combined YAML
```bash
$ pytrust

pypdf:
  file_system: true
  env_vars: false
  web_requests: false
  exec_usage: false
... (the list might be pretty long!)
```



## Permissions YAML Example

In this file you specify which packages are allowed to access certain resources. For example:

```yaml
pypdf:
	file_system: true  # needed to read/write PDF files
	env_vars: false
	web_requests: false
	exec_usage: false
```



## Contributing & Help
- Issues and PRs welcome!




**Made with ❤️ by Martin Thoma and contributors.**
