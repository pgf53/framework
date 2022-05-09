#!/bin/sh

#### Cargar configuracion
	. ./framework_config.sh
	. ./framework_config_interna.sh

OUT_LOG_TMP="$1"

> "${PATH_AUDIT_LOG}"
rm -f "${OUT_LOG_TMP}" 1>/dev/null 2>&1

while true
do
while read j
do
	#tail -1 "${PATH_ACCESS_LOG}" >> "${PATH_LOG}/access_log" #cogemos línea de access_log relativa a la uri lanzada 
	cp "${PATH_AUDIT_LOG}" "${OUT_LOG_TMP}"
	> "${PATH_AUDIT_LOG}"
	break
done <	$(inotifywait -q -e modify ${PATH_ACCESS_LOG} | cut -d ' ' -f1) 
done

