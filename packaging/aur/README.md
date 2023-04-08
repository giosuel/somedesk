# AUR packages

| Package | Builds from | Arch |
| --- | --- | --- |
| [`somedesk`](https://aur.archlinux.org/packages/somedesk) | source of the tagged release | x86_64, aarch64 |
| [`somedesk-bin`](https://aur.archlinux.org/packages/somedesk-bin) | binary tarball of the GitHub release | x86_64 |

Both install the desktop client. Each directory is a copy of the matching AUR git
repository. The files here are the source of truth: change them here, then copy them over.

## Test

```sh
packaging/aur/test.sh
```

Builds both packages in a clean `archlinux:base-devel` container, runs the unit
tests and `namcap`, installs each package and regenerates `.SRCINFO`. Needs podman
or docker. Until the version in the PKGBUILDs is released, it builds from the local
checkout, and makes the binary tarball the way the release workflow does.

The remaining namcap warnings are known false positives: the unused
`ld-linux-x86-64.so.2` (every Rust binary), and "may not be needed" for the X11,
Wayland and OpenGL libraries, which winit and glutin load at runtime.

## Publish (first time)

The checksums are `SKIP` until the first release: the release workflow fills them in
(see below), or run `bump.sh <version>` once the release exists.

Needs an [AUR account](https://aur.archlinux.org/register) with your SSH public key.

```sh
packaging/aur/bump.sh 0.1.0 && packaging/aur/test.sh
for pkg in somedesk somedesk-bin; do
  git clone "ssh://aur@aur.archlinux.org/$pkg.git" "/tmp/aur-$pkg"
  cp "packaging/aur/$pkg/PKGBUILD" "packaging/aur/$pkg/.SRCINFO" "/tmp/aur-$pkg/"
  git -C "/tmp/aur-$pkg" add PKGBUILD .SRCINFO
  git -C "/tmp/aur-$pkg" commit -m "Initial import: $pkg 0.1.0"
  git -C "/tmp/aur-$pkg" push origin master
done
```

## Updates are automatic

When a stable `v*` tag is released, the `aur` jobs in `.github/workflows/release.yml`:

1. set `pkgver` to the tag and `pkgrel=1`,
2. refresh the checksums and build each package in Arch,
3. push `PKGBUILD` and a new `.SRCINFO` to the AUR.

They push with the `AUR_SSH_PRIVATE_KEY` repository secret, a key registered on the
AUR account. Pre-releases (`v1.0.0-rc1`) are skipped.

Change anything else (dependencies, install steps) here first, check it with
`test.sh`, and the next release carries it over. To push an update by hand, run
`bump.sh <version>` and `test.sh`, then copy `PKGBUILD` and `.SRCINFO` over as above.
