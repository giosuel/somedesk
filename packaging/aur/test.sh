#!/usr/bin/env bash
# Build both AUR packages in a clean Arch container, lint them with namcap,
# install them and refresh their .SRCINFO files.   packaging/aur/test.sh
#
# Until the PKGBUILDs' version is released on GitHub, the sources come from the
# local checkout instead, with the binary tarball made like the release workflow.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
engine="$(command -v podman || command -v docker)"
version=$(sed -n 's/^pkgver=//p' "$here/somedesk/PKGBUILD")
localsrc=/dev/null
if ! curl -fsSIL -o /dev/null "https://github.com/giosuel/somedesk/archive/v$version.tar.gz" 2>/dev/null; then
  echo "==> v$version is not released: building from the local checkout"
  localsrc="$(mktemp -d)"
  trap 'rm -rf "$localsrc"' EXIT
  # Tracked and new files, as they are now (deleted ones are skipped).
  (cd "$root" && git ls-files -co --exclude-standard -z |
    tar --ignore-failed-read -czf "$localsrc/somedesk-$version.tar.gz" --null -T - --transform "s,^,somedesk-$version/,")
fi
# shellcheck disable=SC2016 # the script runs inside the container
"$engine" run --rm -v "$here:/aur:Z" -v "$localsrc:/local:ro,Z" -e version="$version" docker.io/archlinux:base-devel bash -euo pipefail -c '
  pacman -Syu --noconfirm --needed namcap >/dev/null
  useradd -m builder
  echo "builder ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/builder
  for pkg in somedesk somedesk-bin; do
    echo "==> $pkg"
    cp -r "/aur/$pkg" "/home/builder/$pkg"
    if [ -d /local ]; then
      if [ "$pkg" = somedesk ]; then
        cp "/local/somedesk-$version.tar.gz" /home/builder/somedesk/
      else
        # The release tarball, as .github/workflows/release.yml makes it.
        src="/home/builder/somedesk/src/somedesk-$version" name="SomeDesk-$version-linux-x64"
        mkdir -p "/tmp/$name/packaging/linux" "/tmp/$name/assets/brand"
        cp "$src/target/release/somedesk" "$src/target/release/somedesk-agent" "$src/README.md" "$src/LICENSE" "/tmp/$name/"
        strip "/tmp/$name/somedesk" "/tmp/$name/somedesk-agent"
        cp "$src"/packaging/linux/ch.giosuel.SomeDesk.* "/tmp/$name/packaging/linux/"
        cp "$src/assets/brand/app-icon.svg" "/tmp/$name/assets/brand/"
        tar -C /tmp -czf "/home/builder/somedesk-bin/$name.tar.gz" "$name"
      fi
    fi
    chown -R builder: "/home/builder/$pkg"
    cd "/home/builder/$pkg"
    namcap PKGBUILD
    su builder -c "makepkg --syncdeps --noconfirm --cleanbuild" >makepkg.log 2>&1 || { tail -40 makepkg.log; exit 1; }
    grep -E "test result|Finished" makepkg.log || true
    su builder -c "makepkg --printsrcinfo" > "/aur/$pkg/.SRCINFO"
    namcap ./*.pkg.tar.zst
    pacman -U --noconfirm ./"$pkg"-[0-9]*.pkg.tar.zst >/dev/null
    somedesk --version
    somedesk-agent --help >/dev/null
    pacman -Ql "$pkg" | grep -v "/$"
    pacman -R --noconfirm "$pkg" >/dev/null
  done
'
