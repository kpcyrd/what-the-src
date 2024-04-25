

### Sync Arch Linux

```
what-the-src plumbing sync-pacman --vendor archlinux --fetch https://github.com/archlinux/state/archive/refs/heads/main.tar.gz -r core-x86_64 -r extra-x86_64 -r core-any -r extra-any -r multilib-x86_64
```

### Sync Debian sid

```
what-the-src plumbing sync-apt --vendor debian http://deb.debian.org/debian/ --release sid
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
