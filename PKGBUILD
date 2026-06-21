# Maintainer: talgarr
pkgname=yubikey-notifier-git
_pkgname=yubikey-notifier
pkgver=r9.ef5d003
pkgrel=1
pkgdesc="Desktop notifier that shows which tool triggered a YubiKey touch (eBPF-based)"
arch=('x86_64')
url="https://github.com/talgarr/yubikey-notifier"
license=('MIT')
depends=('glibc' 'libcap')
makedepends=('git' 'go' 'clang' 'libbpf' 'linux-api-headers')
optdepends=('dunst: notification daemon to display the alerts'
            'mako: notification daemon to display the alerts')
provides=('yubikey-notifier')
conflicts=('yubikey-notifier')
install="$_pkgname.install"
source=("$_pkgname::git+https://github.com/talgarr/yubikey-notifier.git")
sha256sums=('SKIP')

pkgver() {
    cd "$_pkgname"
    printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build() {
    cd "$_pkgname"
    make
}

package() {
    cd "$_pkgname"
    install -Dm755 yubikey-notifier "$pkgdir/usr/bin/yubikey-notifier"
    install -Dm644 tracer.bpf.o "$pkgdir/usr/lib/yubikey-notifier/tracer.bpf.o"
    install -Dm644 packaging/yubikey-notifier.service "$pkgdir/usr/lib/systemd/user/yubikey-notifier.service"
    install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
