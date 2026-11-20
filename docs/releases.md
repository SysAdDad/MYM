# Releases

The public repository is [SysAdDad/MYM](https://github.com/SysAdDad/MYM). It contains
reviewed release source, documentation, tests, and user issues. Development history
is kept in a separate private repository. The two repositories do not synchronize automatically.

## Preparing a release

1. Select a tested development revision. Copy only tracked source and documentation;
   never include `.env`, databases, data volumes, credentials, or private history.
2. Update this repository through a pull request. Keep its release workflow and public
   image name intact. Review the diff, license notices, screenshots, and Compose files.
3. Wait for the container, regression, setup, and persistence checks to pass.
4. Merge, then create a version tag such as `v0.1.0` on the reviewed commit.
5. Wait for that tag's workflow to pass. It publishes `ghcr.io/sysaddad/mym-community`
   with the version, `stable`, and `sha-COMMIT_SHA` tags. Verify anonymous pull access.
6. Publish release notes that identify the source revision, image version, changes,
   migration requirements, and checks that remain unperformed.

Normal pushes and pull requests run tests but do not move `stable`. Never point a
production installation at the private development image. Users choose when to pull
and recreate their containers, retaining the same data volume.

## First release

`v0.1.0` is the first public source release. It includes local first-run setup,
organization branding, local/OIDC/LDAP sign-in, the guided and advanced editors,
templates, exports, and optional contact QR codes. Known follow-up work and testing
limits are recorded in [code-review.md](code-review.md).

The older private `ghcr.io/sysaddad/mym:ce` package is unrelated to this public image.
Existing installations are not automatically migrated or redeployed.
