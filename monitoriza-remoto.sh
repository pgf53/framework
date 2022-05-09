#!/bin/sh

#carga de ficheros de configuración
. ./framework_config.sh
. ./framework_config_interna.sh

OUT_LOG_TMP="$1"
#OUT_ACCESS_TMP="/dev/shm/access_log"

> "${PATH_AUDIT_LOG}"
> "${PATH_ACCESS_LOG}"

#rm -f "${OUT_LOG_TMP}" "${OUT_ACCESS_TMP}" 1>/dev/null 2>&1
rm -f "${OUT_LOG_TMP}" 1>/dev/null 2>&1

while true
do
while read j
	do
		#echo "uri detectada, enviando audit_log...."
		cp "${PATH_AUDIT_LOG}" "${OUT_LOG_TMP}"
#		tail -1 "${PATH_ACCESS_LOG}" > "${OUT_ACCESS_TMP}"
		#cp "${PATH_ACCESS_LOG}" "${OUT_ACCESS_TMP}"
		#sshpass -p ${PASS} scp "${OUT_LOG_TMP}" "${OUT_ACCESS_TMP}" ${USER_REMOTO}@${IP_EQUIPO_LOCAL}://dev/shm/
		if [ "${SSH_PASS}" = "yes" ]; then
			sshpass -p ${PASS} scp "${OUT_LOG_TMP}" ${USER_REMOTO}@${IP_EQUIPO_LOCAL}:/${DIR_TMP_FAST}
		elif [ "${SSH_PASS}" = "no" ]; then
			scp "${OUT_LOG_TMP}" ${USER_REMOTO}@${IP_EQUIPO_LOCAL}:/${DIR_TMP_FAST}
		fi
		> "${PATH_AUDIT_LOG}"
		#> "${PATH_ACCESS_LOG}"
		#rm -f "${OUT_LOG_TMP}" "${OUT_ACCESS_TMP}" 1>/dev/null 2>&1
		rm -f "${OUT_LOG_TMP}" 1>/dev/null 2>&1
		break
	done <	$(inotifywait -q -e modify ${PATH_ACCESS_LOG} | cut -d ' ' -f1) 
done

