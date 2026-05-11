# Maintainer: croaky-fx <217624563+croaky-fx@users.noreply.github.com>
pkgname=oxiclean
pkgver=1.0.4
pkgrel=1
pkgdesc="Fast Cross-Distribution Linux System Cleaner written in Rust"
arch=('x86_64')
url="https://github.com/croaky-fx/oxiclean"
license=('MIT')
depends=('gcc-libs')
makedepends=('rust' 'cargo')
source=("${url}/releases/download/v${pkgver}/${pkgname}-x86_64-linux-gnu"
        "${url}/releases/download/v${pkgver}/${pkgname}-x86_64-linux-musl")
sha256sums=('50b5eb923f02550adc55b485ca6867134e652dde5635d50ae5cc1bbf2b58e24c'
            'ba0e9a2754676457c1e0ec92ff6bc7ea7c3ee2f68dcccbf9f5cebd3422ffeb83')

package() {
  install -Dm755 "${srcdir}/${pkgname}-x86_64-linux-gnu" "${pkgdir}/usr/bin/${pkgname}"
  install -Dm644 LICENSE "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE" 2>/dev/null || true
}
