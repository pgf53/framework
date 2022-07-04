#!/bin/sh

#### Cargar configuracion
. ./framework_config_interna.conf

OUT_LOG="$1"

if [ "${SSH_PASS}" = "yes" ]; then
	sshpass -p ${PASS} scp "${PATH_AUDIT_LOG}" ${USER_REMOTO}@${IP_EQUIPO_LOCAL}:/${OUT_LOG}
elif [ "${SSH_PASS}" = "no" ]; then
	scp "${PATH_AUDIT_LOG}" ${USER_REMOTO}@${IP_EQUIPO_LOCAL}:/${OUT_LOG}
fi
#sshpass -p ${PASS} scp "${PATH_ACCESS_LOG}" ${USER_REMOTO}@${IP_EQUIPO_LOCAL}:/"${DIR_ROOT}/${PATH_LOG}/access_log"
