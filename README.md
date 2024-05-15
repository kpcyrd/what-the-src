

### Sync Arch Linux

```
what-the-src plumbing sync-pacman --vendor archlinux --fetch https://github.com/archlinux/state/archive/refs/heads/main.tar.gz -r core-x86_64 -r extra-x86_64 -r core-any -r extra-any -r multilib-x86_64
```

### Sync Debian

```
what-the-src plumbing sync-apt --vendor debian http://deb.debian.org/debian/ --release sid --release stable
what-the-src plumbing sync-apt --vendor debian https://security.debian.org/debian-security/ --release stable-security
```

### Sync Fedora rawhide

```
what-the-src plumbing sync-rpm --vendor fedora https://ftp.halifax.rwth-aachen.de/fedora/linux/development/rawhide/Everything/source/tree/
```

### Sync Alpine

```
what-the-src plumbing sync-alpine --vendor alpine --fetch https://ftp.halifax.rwth-aachen.de/alpine/edge/main/x86_64/APKINDEX.tar.gz --repo main
what-the-src plumbing sync-alpine --vendor alpine --fetch https://ftp.halifax.rwth-aachen.de/alpine/edge/community/x86_64/APKINDEX.tar.gz --repo community
```

### Sync openSUSE

```
what-the-src plumbing sync-rpm --vendor opensuse https://ftp.halifax.rwth-aachen.de/opensuse/tumbleweed/repo/src-oss/
```

### Sync Gentoo

```
what-the-src plumbing sync-gentoo --vendor gentoo --fetch https://github.com/gentoo-mirror/gentoo/archive/refs/heads/master.tar.gz
```

### Sync Homebrew

```
what-the-src plumbing sync-homebrew --vendor homebrew --fetch https://formulae.brew.sh/api/formula.json
```

### Sync Wolfi OS

```
what-the-src plumbing sync-alpine --vendor wolfi --fetch https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz
```

### Sync Guix

```
what-the-src plumbing sync-guix --vendor guix --fetch 'https://guix.gnu.org/packages.json'
```
