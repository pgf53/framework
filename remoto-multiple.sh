#!/bin/sh

#carga de ficheros de configuración
. ./framework_config.sh
. ./framework_config_interna.sh

OUT_LOG="$1"
byobu new-session -s "${BYOBU_SESSION}" -d "cd ${DIR_REMOTE}; ./${SEND_LOG_SCRIPT} ${OUT_LOG}"
