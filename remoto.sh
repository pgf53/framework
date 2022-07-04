#!/bin/sh

#### Cargar configuracion
. ./framework_config_interna.conf

OUT_LOG_TMP="$1"

byobu new-session -s "${BYOBU_SESSION}" -d "cd ${DIR_REMOTE}; ./${REMOTE_MONITORIZATION_SCRIPT} ${OUT_LOG_TMP}"
