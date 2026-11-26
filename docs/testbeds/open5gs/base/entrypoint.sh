#!/bin/sh
set -e

case "$NF_BIN" in
open5gs-webui)
  cd /opt/open5gs/webui
  exec npm run dev
  ;;
*)
  exec "${INSTALL_PREFIX}/bin/${NF_BIN:?NF_BIN is not set}" -c "${NF_CFG:?NF_CFG is not set}"
  ;;
esac
