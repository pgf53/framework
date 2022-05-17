#!/bin/sh


##########CASO 1-1###############

#Patrones
PATRONPLinicio='[tag "paranoia-level/'
PATRONPLfin='"]'
PL=""

#Cogemos Timestamp
TIMESTAMP_1=$(head -2 02-Log/0days.log | tail -1 | cut -d' ' -f'1')
TIMESTAMP_2=$(head -2 02-Log/0days.log | tail -1 | cut -d' ' -f'2')
TIMESTAMP="${TIMESTAMP_1} ${TIMESTAMP_2}"

#Uri la cogemos de fichero de entrada (la que se ha lanzado)
URI="$1"
LINEAS_LOG=$(wc -l 02-Log/0days.log | cut -d' ' -f'1')

#Eliminamos secciones iniciales y finales
LINEAS_SECCIONES_INICIALES=14
LINEAS_SECCIONES_FINALES=7
LINEAS_SIN_SECCIONES_INICIALES=$(tail -$((LINEAS_LOG-LINEAS_SECCIONES_INICIALES)) 02-Log/0days.log | wc -l)
tail -$((LINEAS_LOG-LINEAS_SECCIONES_INICIALES)) 02-Log/0days.log | head -$((LINEAS_SIN_SECCIONES_INICIALES-LINEAS_SECCIONES_FINALES)) > /dev/shm/seccionhtmp


printf "TimeStamp %s\tUri %s\n" "${TIMESTAMP}" "[${URI}]" > prueba_1-1.index
