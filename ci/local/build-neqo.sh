#!/usr/bin/env bash
# Run in the exact cargo-chef base from pinned Neqo's qns/Dockerfile. Uses the
# same NSS digest, flags and final cargo command; skips only chef cache layers.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export SSL_CERT_FILE=/run/system-ca.pem CURL_CA_BUNDLE=/run/system-ca.pem
export CARGO_HTTP_CAINFO=/run/system-ca.pem
apt-get -o Acquire::https::CaInfo=/run/system-ca.pem update
apt-get -o Acquire::https::CaInfo=/run/system-ca.pem install -y --no-install-recommends libclang-dev gyp ninja-build python-is-python3 jq
cp -a /source /neqo
cd /neqo
rustc --version
cargo metadata --locked --format-version=1 -q | jq -r '.packages[] | select(.name=="nss-rs") | .metadata.nss | "NSS_VERSION=" + .["min-version"], "NSS_SHA256=" + .sha256' > /tmp/nss.env
source /tmp/nss.env
NSS_TAG=${NSS_VERSION//./_}
RELEASE_DIR="https://ftp.mozilla.org/pub/security/nss/releases/NSS_${NSS_TAG}_RTM/src"
FILENAME=$(curl -fsSL "$RELEASE_DIR/SHA256SUMS" | awk -v digest="$NSS_SHA256" '$1==digest {sub(/^\*/, "", $2); print $2}')
case "$FILENAME" in nss-*-with-nspr-*.tar.gz) ;; *) exit 1 ;; esac
curl -fL -o /tmp/nss.tar.gz "$RELEASE_DIR/$FILENAME"
printf '%s  /tmp/nss.tar.gz\n' "$NSS_SHA256" | sha256sum --check
tar xzf /tmp/nss.tar.gz --strip-components=1 -C /
export NSS_DIR=/nss NSS_TARGET=Release NSS_PREBUILT=1 NSPR_DIR=/nspr LD_LIBRARY_PATH=/dist/Release/lib
"$NSS_DIR"/build.sh --static -Ddisable_tests=1 -Ddisable_dbm=1 -Ddisable_libpkix=1 -Ddisable_ckbi=1 -Ddisable_fips=1 -o
CARGO_PROFILE_RELEASE_DEBUG=true CARGO_BUILD_JOBS=2 cargo build --locked --release --bin neqo-client --bin neqo-server
mkdir -p /output/bin /output/lib
cp target/release/neqo-client target/release/neqo-server /dist/Release/bin/certutil /dist/Release/bin/pk12util /output/bin/
cp /dist/Release/lib/*.so /output/lib/
cp qns/interop.sh /output/interop.sh
chmod a+r /output/interop.sh
sha256sum /output/bin/* /output/lib/* /output/interop.sh > /output/artifacts.sha256
chmod a+r /output/artifacts.sha256
