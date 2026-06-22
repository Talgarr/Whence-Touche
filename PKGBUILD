# Maintainer: talgarr
pkgname=whence-touche-git
_pkgname=whence-touche
pkgver=r21.0cb9362
pkgrel=1
pkgdesc="Whence Touché — shows which tool triggered a YubiKey touch (eBPF-based)"
arch=('x86_64')
url="https://github.com/Talgarr/Whence-Touche"
license=('MIT')
depends=('glibc' 'libcap')
makedepends=('git' 'go' 'clang' 'libbpf' 'linux-api-headers')
optdepends=('dunst: notification daemon to display the alerts'
            'mako: notification daemon to display the alerts')
provides=('whence-touche')
conflicts=('whence-touche')
install="$_pkgname.install"
source=("$_pkgname::git+https://github.com/Talgarr/Whence-Touche.git")
sha256sums=('SKIP')

pkgver() {
    cd "$_pkgname"
    printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build() {
    cd "$_pkgname"
    make build
}

package() {
    cd "$_pkgname"
    install -Dm755 whence-touche "$pkgdir/usr/bin/whence-touche"
    install -Dm644 packaging/whence-touche.service "$pkgdir/usr/lib/systemd/user/whence-touche.service"
    install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
