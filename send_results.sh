#!/bin/sh

#### Cargar configuracion
. ./framework_config.sh
. ./framework_config_interna.sh
. ../config_interna.sh


#Usado en cloud. Envía los resultados del análisis del equipo local al equipo original que ejecutó cloud.
#se ejecuta en equipo que realiza los análisis
#Recibe como argumento el nombre del fichero a enviar

parsed_file_name="$1"

#Obtenemos nombre de equipo local 
nombre_equipo=$(ls ./.. | grep .tar.gz | cut -d'-' -f1)

#Borramos si existe el directorio de Resultados 
rm -rf "${RESULTADOS_CLOUD}" "${RESULTADOS_CLOUD}_${nombre_equipo}"

#Creamos directorios y subdirectorios de resultados
mkdir "${DIR_ROOT}/${RESULTADOS_CLOUD}/"
mkdir "${DIR_ROOT}/${RESULTADOS_CLOUD}/${DIRIN_URI}/"
mkdir "${DIR_ROOT}/${RESULTADOS_CLOUD}/${PATH_LOG}/"
mkdir "${DIR_ROOT}/${RESULTADOS_CLOUD}/${DIROUT_INDEX}/"
mkdir "${DIR_ROOT}/${RESULTADOS_CLOUD}/${DIROUT_ATTACKS}/"
mkdir "${DIR_ROOT}/${RESULTADOS_CLOUD}/${DIROUT_CLEAN}/"

#Copiamos resultados de análisis a directorio de resultados Cloud
#Entrada
cp "${DIR_ROOT}/${DIRIN_URI}/${parsed_file_name}${FILE_IN_EXTENSION}" "${RESULTADOS_CLOUD}/${DIRIN_URI}/"
#Log
cp "${DIR_ROOT}/${PATH_LOG}/${parsed_file_name}${LOG_EXTENSION}" "${RESULTADOS_CLOUD}/${PATH_LOG}/"
#Index
cp "${DIR_ROOT}/${DIROUT_INDEX}/${parsed_file_name}${INDEX_EXTENTION}" "${RESULTADOS_CLOUD}/${DIROUT_INDEX}/"
#Ataques
cp "${DIR_ROOT}/${DIROUT_ATTACKS}/${parsed_file_name}${ATTACKS_EXTENSION}" "${RESULTADOS_CLOUD}/${DIROUT_ATTACKS}/"
cp "${DIR_ROOT}/${DIROUT_ATTACKS}/${parsed_file_name}${INFO_ATTACKS_EXTENSION}" "${RESULTADOS_CLOUD}/${DIROUT_ATTACKS}/"
[ -f "${DIR_ROOT}/${DIROUT_ATTACKS}/${parsed_file_name}${INFO_ATTACKS_HIDE_EXTENSION}" ] && cp "${DIR_ROOT}/${DIROUT_ATTACKS}/${parsed_file_name}${INFO_ATTACKS_HIDE_EXTENSION}" "${RESULTADOS_CLOUD}/${DIROUT_ATTACKS}/"
#Limpias
cp "${DIR_ROOT}/${DIROUT_CLEAN}/${parsed_file_name}${CLEAN_EXTENSION}" "${RESULTADOS_CLOUD}/${DIROUT_CLEAN}"

#Incluimos en el nombre del directorio de resultados, el nombre del equipo que ha realizado el análisis
mv "${RESULTADOS_CLOUD}" "${RESULTADOS_CLOUD}_${nombre_equipo}"

#Transferimos el directorio de resultados a equipo origen que ejecutó cloud
tar czvf "${RESULTADOS_CLOUD}_${nombre_equipo}.tar.gz" "${RESULTADOS_CLOUD}_${nombre_equipo}"
if [ "${SSH_PASS}" = "yes" ]; then
	sshpass -p "${PASS_CLOUD}" scp "${DIR_ROOT}/${RESULTADOS_CLOUD}_${nombre_equipo}.tar.gz" "${USER_CLOUD}"@"${SOURCE_DEVICE}":"${DIR_CLOUD}/"
	#Movemos a directorio 'Comprimidos' para desencadenar el evento
	sshpass -p "${PASS}" ssh "${USER_CLOUD}"@"${SOURCE_DEVICE}" "cd ${DIR_CLOUD}/; mv ${RESULTADOS_CLOUD}_${nombre_equipo}.tar.gz ${RESULTADOS_COMPRIMIDOS} 1>/dev/null 2>&1"
elif [ "${SSH_PASS}" = "no" ]; then
	scp "${DIR_ROOT}/${RESULTADOS_CLOUD}_${nombre_equipo}.tar.gz" "${USER_CLOUD}"@"${SOURCE_DEVICE}":"${DIR_CLOUD}/"
	#Movemos a directorio 'Comprimidos' para desencadenar el evento
	ssh "${USER_CLOUD}"@"${SOURCE_DEVICE}" "cd ${DIR_CLOUD}/; mv ${RESULTADOS_CLOUD}_${nombre_equipo}.tar.gz ${RESULTADOS_COMPRIMIDOS} 1>/dev/null 2>&1"
fi
