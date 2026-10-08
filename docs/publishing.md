# PyPI trusted publishing

Package name availability is provisional until registration. Configure a pending trusted publisher in the PyPI account that should own SecuLens:

- PyPI project name: `seculens`
- GitHub owner: `masahirocom`
- GitHub repository: `seculens-python`
- Workflow filename: `publish.yml`
- Environment: `pypi`

Use https://pypi.org/manage/account/publishing/ and follow https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/ . No API token needs to be shared in chat. After configuration, run the Publish to PyPI workflow or publish a GitHub release. The workflow tests and audits the project, builds distribution files, validates them, and publishes through OIDC.

Verification: `pip index versions seculens`, install the published version into a fresh environment, check `seculens --version`, then scan the demonstration SBOM. The demonstration snapshot is not production vulnerability data.
