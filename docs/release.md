# Releasing

A release is published from a tag, by the `Release` workflow
(`.github/workflows/release.yml`). The three artifacts and their parent POM
(`secret-service-parent`, `secret-service`, `secret-service-hardened`,
`secret-service-hardened-tpm2`) go to Maven Central together, at one version.

## Publish a release

1. On `main`, set the new version wherever the old one is named (`git grep` finds them): the
   parent POM, the three module POMs and `tools/gui/pom.xml`, the README and the docs pages
   with dependency snippets. Set the release date in `CHANGELOG.md`, and merge.
2. Tag that commit with `v` and the version, and push the tag:

    ```sh
    git tag -a v4.0.0 -m "secret-service 4.0.0"
    git push origin v4.0.0
    ```

3. The workflow's first job, which has no secrets, checks that the tag names the project
   version, runs the logging check, builds the jars with their javadoc and runs the regression
   tests, then the system tests against gnome-keyring.
4. The second job runs in the `release` environment and waits for a required reviewer to
   approve it. It runs `mvn deploy`, which signs each artifact and uploads all of them to the
   [Central Portal](https://central.sonatype.com/publishing/deployments) as one deployment,
   and waits until Central has validated it.
5. `autoPublish` is false, so the deployment waits in the Central Portal. Publish it there,
   or drop it.

A failed run can run again by hand on the same tag (*Run workflow*, *Use workflow from*: the
tag). A run on a branch fails at the version check.

## Set up the `release` environment

The repository needs this once. In *Settings*, *Environments*, create the environment
`release`:

- *Required reviewers*: the maintainers, so that each publish waits for an approval.
- *Deployment branches and tags*: *Selected branches and tags*, with the tag rule `v*`, so
  that no run on a branch can read the secrets.
- *Environment secrets*:

| Secret | Value |
|---|---|
| `CENTRAL_TOKEN_USERNAME` | The user name of a Central Portal user token (*central.sonatype.com*, *View Account*, *Generate User Token*), for an account that can publish to the namespace `de.swiesend`. |
| `CENTRAL_TOKEN_PASSWORD` | The password of that token. |
| `GPG_PRIVATE_KEY` | The signing key, ASCII-armored: `gpg --armor --export-secret-keys <key id>`. Its public key must be on a key server that Central reads, such as `keyserver.ubuntu.com` or `keys.openpgp.org`. |
| `GPG_PASSPHRASE` | The passphrase of that key. |

The secrets reach only the publish job. `actions/setup-java` writes the token into Maven's
`settings.xml` as the server `central`, which `central-publishing-maven-plugin` reads, and
imports the key for `maven-gpg-plugin`.
