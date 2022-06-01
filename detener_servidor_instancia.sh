#!/bin/sh

#### Cargar configuracion
. ./framework_config.sh
. ./framework_config_interna.sh


if [ "${MODSECURITY_ONLINE}" -eq 1 ]; then
	httpd -f "${FILE_CONFIG_APACHE}" -k stop
elif [ "${NEMESIDA_ONLINE}" -eq 1 ]; then
	PID_LIST=$(lsof -i -P -n | grep :80 | grep nginx | awk '{print $2}')
	for PID in ${PID_LIST}; do
		kill -9 ${PID}
	done
fi
