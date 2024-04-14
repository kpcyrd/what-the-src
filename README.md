

### Sync Arch Linux

```
what-the-src plumbing sync-pacman --vendor archlinux --fetch https://github.com/archlinux/state/archive/refs/heads/main.tar.gz -r core-x86_64 -r extra-x86_64 -r core-any -r extra-any -r multilib-x86_64
```

### Sync Debian sid

```
what-the-src plumbing sync-apt --vendor debian --fetch http://deb.debian.org/debian/dists/sid/main/source/Sources.xz
```

### Sync Fedora rawhide

```
what-the-src plumbing sync-rpm --vendor fedora --fetch https://ftp.halifax.rwth-aachen.de/fedora/linux/development/rawhide/Everything/source/tree/
```
