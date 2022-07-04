#!/bin/sh

#### Cargar configuracion
. ./framework_config_interna.conf

OUT_LOG="$1"
byobu new-session -s "${BYOBU_SESSION}" -d "cd ${DIR_REMOTE}; ./${SEND_LOG_SCRIPT} ${OUT_LOG}"
