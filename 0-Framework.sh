#!/bin/sh

#Introducimos ruta raíz de la herramienta
DIR_ROOT=$(pwd)
sed -i "s#DIR_ROOT=.*#DIR_ROOT=\"${DIR_ROOT}\"#g" "framework_config_interna.sh"

#### Cargar configuracion
. ./framework_config.sh
. ./framework_config_interna.sh


#funciones
imprimirCabecera ()
{

	OUT_ATTACKS_INFO="$1"
	OUT_ATTACKS_INFO_HIDE="$2"
	OUT_CLEAN="$3"
	OUT_ATTACKS="$4"

	#si "HIDE_COLUMMNS" = "yes" eliminamos columnas opcionales
	COLUMNS=$(printf "%s %s" ${OPTIONAL_COLUMNS} | tr " " ",")
	if [ -f "${OUT_ATTACKS_INFO}" -a "${HIDE_COLUMNS}" = "yes" ]; then
		cut --complement -d'	' -f${COLUMNS} "${OUT_ATTACKS_INFO}" >> "${OUT_ATTACKS_INFO_HIDE}"
	fi

	#Imprimimos cabecera resumen de fichero "*-info.attacks"
	if [ -f "${OUT_CLEAN}" ]; then
		num_clean=$(wc -l "${OUT_CLEAN}" | cut -d' ' -f1)
	else
		num_clean=0
	fi

	if [ -f "${OUT_ATTACKS}" ]; then
		num_ataques=$(wc -l "${OUT_ATTACKS}" | cut -d' ' -f1)
	else
		num_ataques=0
	fi

	IMPRIMIR1="---------------------- Statistics of URIs analyzed------------------------"
	IMPRIMIR2="[${uris_totales}] input, [${num_clean}] clean, [${num_ataques}] attacks"
	IMPRIMIR3="--------------------------- Analysis results -----------------------------"

	if [ ! -f "${OUT_ATTACKS_INFO}" ]; then 
		printf "%s\n%s\n%s" "${IMPRIMIR1}" "${IMPRIMIR2}" "${IMPRIMIR3}" >> "${OUT_ATTACKS_INFO}"
	else
		sed -i "1i$IMPRIMIR3"  "${OUT_ATTACKS_INFO}"
		sed -i "1i$IMPRIMIR2"  "${OUT_ATTACKS_INFO}"
		sed -i "1i$IMPRIMIR1"  "${OUT_ATTACKS_INFO}"

		#Imprimimos cabecera en fichero "*-info_hide.attacks" si existe
		if [ -f "${OUT_ATTACKS_INFO_HIDE}" ]; then
			sed -i "1i$IMPRIMIR3"  "${OUT_ATTACKS_INFO_HIDE}"
			sed -i "1i$IMPRIMIR2"  "${OUT_ATTACKS_INFO_HIDE}"
			sed -i "1i$IMPRIMIR1"  "${OUT_ATTACKS_INFO_HIDE}"
		fi
	fi
}

#Comprobación del formato de fichero uri de entrada
comprobar_formato()
{
	fichero_uri="$1"
	while IFS= read -r uri
	do
		var=$(printf "%s" "${uri}" | grep -P '\t')
		var=$?
		if [ "${var}" -eq 0 -a "${URIS_FORMAT}" = "basic" ]; then 
			echo "URIS_FORMAT inválido. El formato de entrada \"${URIS_FORMAT}\" seleccionado no se corresponde con entrada:"
			printf "%s" "${URI}"
			echo "Se sale..."
			exit 1
		elif [ "${var}" -eq 1 -a "${URIS_FORMAT}" = "extended" ]; then 
			echo "URIS_FORMAT inválido. El formato de entrada \"${URIS_FORMAT}\" seleccionado no se corresponde con entrada:"
			printf "%s" "${URI}"
			echo "Se sale..."
			exit 1
		fi
		break	#Se analiza solo una, se entiende que todas presentan el mismo formato.
	done < "${i}"
}

#### Main ######
if [ ! -d "${DIRIN_URI}" ]; then 
	echo "${DIRIN_URI} no existe. Se sale..."
	exit 1
fi


#OJO! TEN EN CUENTA QUE BORRAS LOS RESULTADOS EN CAJA EJECUCIÓN DE FRAMEWORK
rm -rf "${PATH_LOG}" "${DIROUT_INDEX}" "${DIROUT_ATTACKS}" "${DIROUT_CLEAN}" "${RESULTADOS}" 1>/dev/null 2>&1
mkdir "${PATH_LOG}" "${DIROUT_INDEX}" "${DIROUT_ATTACKS}" "${DIROUT_CLEAN}" "${RESULTADOS}" 1>/dev/null 2>&1

#Cargo variables para analizador y clasificador
set -a; source "${DIR_ROOT}/framework_config.sh"; set +a
set -a; source "${DIR_ROOT}/framework_config_interna.sh"; set +a

#Nos aseguramos de que todas las uris de fichero de entrada empiecen por caracter '/'
./"${ANADE_BARRA}" "${DIR_ROOT}/${DIRIN_URI}/"

#Comprobamos ejecución IL

if [ "${IL}" -ne 1 ]; then 
	#Configuramos instancia de apache y arrancamos servidor
	[ "${LAUNCH_TYPE}" = "online-local" ] && ./"${CONFIGURA_INSTANCIA_APACHE}"
	#recorremos directorio de entrada con los ficheros a evaluar.
	for i in "${DIR_ROOT}/${DIRIN_URI}/"* ; do
		printf "\n${i}\n"
		if [ ! -f "${i}" ]; then 
			echo "No existe el fichero de entrada. Se sale..."
			exit 1
		fi

		FILENAME="$(basename ${i%.*})${FILE_IN_EXTENSION}"
		if [ "${NO_REPEAT}" = "yes" ]; then
			cp "${i}" "${DIR_TMP}/${FILENAME}"
			"${DIR_ROOT}/${NO_REPEAT_SCRIPT}" "${i}" "${URIS_FORMAT}" ${DIR_ROOT}	#Crea nuevo fichero eliminando uris repetidas
		fi

		#Comprobamos formato de fichero de entrada a evaluar
		comprobar_formato "${i}"

		OUT_ATTACKS_INFO="${DIR_ROOT}/${DIROUT_ATTACKS}/$(basename ${i%.*})${INFO_ATTACKS_EXTENSION}"
		OUT_ATTACKS_INFO_HIDE="${DIR_ROOT}/${DIROUT_ATTACKS}/$(basename ${i%.*})${INFO_ATTACKS_HIDE_EXTENSION}"
		OUT_CLEAN="${DIR_ROOT}/${DIROUT_CLEAN}/$(basename ${i%.*})${CLEAN_EXTENSION}"
		OUT_ATTACKS="${DIR_ROOT}/${DIROUT_ATTACKS}/$(basename ${i%.*})${ATTACKS_EXTENSION}"
		OUT_LOG="${DIR_ROOT}/${PATH_LOG}/$(basename ${i%.*})${LOG_EXTENSION}"	#fichero donde queda regisrado el audit_log
		OUT_LOG_TMP="${DIR_TMP_FAST}/${NOMBRE_RAIZ}_$(basename ${i%.*})${LOG_EXTENSION}"	#fichero donde queda registrado el log relativo a una uri (temporal)
		OUT_INDEX="${DIR_ROOT}/${DIROUT_INDEX}/$(basename ${i%.*})${INDEX_EXTENTION}"	#fichero de index generado
		uris_totales=$(wc -l "${i}" | cut -d' ' -f1)

		#################################1-1#############################
		case "${LAUNCH_MODE}" in
			1to1)
				printf "\nEjecutando modo de lanzamiento 1 a 1\n"

					if [ "${LAUNCH_TYPE}" = "online-local" ]; then
						> "${PATH_ACCESS_LOG}"
						byobu new-session -s "${BYOBU_SESSION}" -d "${DIR_ROOT}/${LOCAL_MONITORIZATION_SCRIPT} ${OUT_LOG_TMP}"	#monitorizamos acces_log, ante un cambio entramos en "fase 2 análisis"
					elif [ "${LAUNCH_TYPE}" = "online-remoto" -a "${SSH_PASS}" = "yes" ]; then

						sshpass -p "${PASS}" ssh "${USER_REMOTE}"@${IP_REMOTE} "> ${PATH_ACCESS_LOG}; cd ${DIR_REMOTE}; rm -f ${REMOTE_SCRIPT} ${REMOTE_MONITORIZATION_SCRIPT} framework_config.sh framework_config_interna.sh 1>/dev/null 2>&1"	#preparamos directorio

						sshpass -p "${PASS}" scp "${DIR_ROOT}/${REMOTE_SCRIPT}" "${DIR_ROOT}/${REMOTE_MONITORIZATION_SCRIPT}" "${DIR_ROOT}/framework_config.sh" "${DIR_ROOT}/framework_config_interna.sh" "${USER_REMOTE}"@"${IP_REMOTE}":${DIR_REMOTE}	#transferimos script a ejecutar en equipo remoto para monitorizar

						sshpass -p "${PASS}" ssh "${USER_REMOTE}"@${IP_REMOTE} "cd ${DIR_REMOTE}; ./${REMOTE_SCRIPT} ${OUT_LOG_TMP}" < /dev/null	#ejecutamos script. ("remoto" invoca a "monitoriza-remoto" en nueva sesión byobu)

					elif [ "${LAUNCH_TYPE}" = "online-remoto" -a "${SSH_PASS}" = "no" ]; then

						ssh "${USER_REMOTE}"@${IP_REMOTE} "> ${PATH_ACCESS_LOG}; cd ${DIR_REMOTE}; rm -f ${REMOTE_SCRIPT} ${REMOTE_MONITORIZATION_SCRIPT} framework_config.sh framework_config_interna.sh 1>/dev/null 2>&1"	#preparamos directorio

						scp "${DIR_ROOT}/${REMOTE_SCRIPT}" "${DIR_ROOT}/${REMOTE_MONITORIZATION_SCRIPT}" "${DIR_ROOT}/framework_config.sh" "${DIR_ROOT}/framework_config_interna.sh" "${USER_REMOTE}"@"${IP_REMOTE}":${DIR_REMOTE}	#transferimos script a ejecutar en 																																												equipo remoto para monitorizar
						ssh "${USER_REMOTE}"@${IP_REMOTE} "cd ${DIR_REMOTE}; ./${REMOTE_SCRIPT} ${OUT_LOG_TMP}" < /dev/null	#ejecutamos script. ("remoto" invoca a "monitoriza-remoto" en nueva sesión byobu)
					fi

					printf "\nAnálisis en progreso...\n\n"
					uri_actual=1
					while IFS= read -r input	#Si el formato es "basico" "input=uri lanzada".
					do
						#Fase 1: Lanzamiento
						#Creamos fichero en memoria de una sola uri. El nombre estará creado a partir de directorio de la herramienta de forma que sea único
						printf "%s\n" "${input}" > "${DIR_TMP_FAST}/1to1_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}"
						if [ "${LAUNCH_TYPE}" = "online-local" -o "${LAUNCH_TYPE}" = "online-remoto" ]; then 
							rm -f "${OUT_LOG_TMP}" 1>/dev/null 2>&1	#eliminamos fichero de log temporal de uri anterior
						elif [ "${LAUNCH_TYPE}" = "offline" ]; then 
							> "${PATH_AUDIT_LOG}"	#Limpiamos audit_log en cada ejecución
							rm -f "${OUT_LOG_TMP}"	#Borramos fichero de log de uri anterior
						fi
						"${DIR_ROOT}/${LAUNCHER_SCRIPT}" "${DIR_TMP_FAST}/1to1_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}"	#Realizamos el lanzamiento de la uri.

						if [ "${LAUNCH_TYPE}" = "offline" ]; then
							cat "${PATH_AUDIT_LOG}" > "${OUT_LOG_TMP}"
							cat "${PATH_AUDIT_LOG}" >> "${OUT_LOG}"
						fi

						if [ "${LAUNCH_TYPE}" = "online-local" -o "${LAUNCH_TYPE}" = "online-remoto" ]; then 
							while true
							do
								if [ -f "${OUT_LOG_TMP}" ]; then
									cat "${OUT_LOG_TMP}" >> "${OUT_LOG}"
									break
								fi
							done
						fi

						#Fase 2: Análisis
						if [ "${URIS_FORMAT}" = "basic" ]; then
							uri_entrada="${input}"
						else
							uri_entrada=$(printf "%s" "${input}" | cut -d'	' -f2)
						fi

						"${DIR_ROOT}/${ANALYZER_SCRIPT}" "${OUT_LOG_TMP}" "${uri_entrada}"

						#Fase 3 Clasificador
		#			./3-classify.sh "${input}" "${OUT_INDEX}" "${OUT_ACCESS}" "${uri_actual}"	#el fichero de access solo es necesario para la modalidad "online"  ${PATH_ACCESS_LOG} ${OUT_ACCESS}
					#pasamos última línea de fichero .index
					mv "${DIROUT_INDEX}/${NOMBRE_RAIZ}_$(basename ${i%.*})${INDEX_EXTENTION}" "${OUT_INDEX}"
					[ -s "${OUT_INDEX}" ] && last_line_index=$(tail -1 "${OUT_INDEX}") || last_line_index="uri_limpia"
					"${DIR_ROOT}/${CLASSIFY_SCRIPT}" "${i}" "${uris_totales}" "${last_line_index}" "${input}" "${uri_actual}"

						printf "\r                                          "
						printf "\r(%s/%s)"  "${uri_actual}"  "${uris_totales}" 
						uri_actual=$((uri_actual+1))	#Incrementamos contador de lectura
					done < "${i}"
				printf "\n"
				[ "${LAUNCH_TYPE}" = "online-local" ] && byobu kill-session -t "${BYOBU_SESSION}"
				[ "${LAUNCH_TYPE}" = "online-remoto" -a "${SSH_PASS}" = "yes" ] && sshpass -p "${PASS}" ssh "${USER_REMOTE}"@${IP_REMOTE} "byobu kill-session -t ${BYOBU_SESSION}"
				[ "${LAUNCH_TYPE}" = "online-remoto" -a "${SSH_PASS}" = "no" ] && ssh "${USER_REMOTE}"@${IP_REMOTE} "byobu kill-session -t ${BYOBU_SESSION}"
				[ "${LAUNCH_TYPE}" = "online-local" -o "${LAUNCH_TYPE}" = "online-remoto" ] && rm -f "${OUT_LOG_TMP}" #"${OUT_ACCESS}"
				#Borrar access_log de 02B-Log y añadir cabeceras 
					imprimirCabecera "${OUT_ATTACKS_INFO}" "${OUT_ATTACKS_INFO_HIDE}" "${OUT_CLEAN}" "${OUT_ATTACKS}"
			;;


			#################################MÚLTIPLE#############################
			multiple)
				printf "\nEjecutando modo de lanzamiento múltiple\n"

					#Si el tipo de lanzamiento es "online-local" u "offline"
					if [ "${LAUNCH_TYPE}" = "online-local" -o "${LAUNCH_TYPE}" = "offline" ]; then 
					> "${PATH_AUDIT_LOG}"	#Limpiamos audit_log
					[ "${LAUNCH_TYPE}" = "online-local" ] && > "${PATH_ACCESS_LOG}"	#Limpiamos access_log
					elif [ "${LAUNCH_TYPE}" = "online-remoto" -a "${SSH_PASS}" = "yes" ]; then
						#Preparamos entorno de trabajo en equipo remoto
						sshpass -p "${PASS}" ssh "${USER_REMOTE}"@${IP_REMOTE} "> ${PATH_ACCESS_LOG}; > ${PATH_AUDIT_LOG}; cd ${DIR_REMOTE}; rm -f ${REMOTE_MULTIPLE_SCRIPT} ${SEND_LOG_SCRIPT} framework_config.sh framework_config_interna.sh 1>/dev/null 2>&1"
						sshpass -p "${PASS}" scp "${DIR_ROOT}/${REMOTE_MULTIPLE_SCRIPT}" "${DIR_ROOT}/${SEND_LOG_SCRIPT}" "${DIR_ROOT}/framework_config.sh" "${DIR_ROOT}/framework_config_interna.sh" "${USER_REMOTE}"@"${IP_REMOTE}":${DIR_REMOTE}
					elif [ "${LAUNCH_TYPE}" = "online-remoto" -a "${SSH_PASS}" = "no" ]; then
						#Preparamos entorno de trabajo en equipo remoto
						ssh "${USER_REMOTE}"@${IP_REMOTE} "> ${PATH_ACCESS_LOG}; > ${PATH_AUDIT_LOG}; cd ${DIR_REMOTE}; rm -f ${REMOTE_MULTIPLE_SCRIPT} ${SEND_LOG_SCRIPT} framework_config.sh framework_config_interna.sh 1>/dev/null 2>&1"
						scp "${DIR_ROOT}/${REMOTE_MULTIPLE_SCRIPT}" "${DIR_ROOT}/${SEND_LOG_SCRIPT}" "${DIR_ROOT}/framework_config.sh" "${DIR_ROOT}/framework_config_interna.sh" "${USER_REMOTE}"@"${IP_REMOTE}":${DIR_REMOTE}
					fi

					uri_actual=1

					#Fase 1: Lanzamiento
					printf "\nIniciando lanzamiento...\n\n"
					"${DIR_ROOT}/${LAUNCHER_SCRIPT}" "${i}"
					if [ "${LAUNCH_TYPE}" = "online-local" -o "${LAUNCH_TYPE}" = "offline" ]; then
						cp "${PATH_AUDIT_LOG}" "${OUT_LOG}"	#Una vez hemos finalizado el lanzamiento, almacenamos el log generado
					elif [ "${LAUNCH_TYPE}" = "online-remoto" -a "${SSH_PASS}" = "yes" ]; then
						sshpass -p "${PASS}" ssh "${USER_REMOTE}"@${IP_REMOTE} "cd ${DIR_REMOTE}; ./${REMOTE_MULTIPLE_SCRIPT} ${OUT_LOG}" < /dev/null
					elif [ "${LAUNCH_TYPE}" = "online-remoto" -a "${SSH_PASS}" = "no" ]; then
						ssh "${USER_REMOTE}"@${IP_REMOTE} "cd ${DIR_REMOTE}; ./${REMOTE_MULTIPLE_SCRIPT} ${OUT_LOG}" < /dev/null
					fi

					#esperamos a que se descarguen del equipo remoto los ficheros de "audit" y "access" 
					if [ "${LAUNCH_TYPE}" = "online-remoto" ]; then 
							while true
								do
									#if [ -f "${OUT_LOG}" -a -f "${OUT_ACCESS}" ]; then
									if [ -f "${OUT_LOG}" ]; then
										break
									fi
								done
					fi

					SECCIONA="-A--"
					num_uris_log=$(cat "${OUT_LOG}" | grep -c ".*${SECCIONA}.*")
					#Fase 2: Análisis
					printf "\nIniciando análisis...\n\n"
					"${DIR_ROOT}/${ANALYZER_SCRIPT}" "${OUT_LOG}" "${num_uris_log}"
					printf "\n\n"

					#Fase 3 Clasificador
					printf "\nIniciando clasificador...\n\n"
					#./3-classify.sh "${i}" "${OUT_INDEX}" "${OUT_ACCESS}"	#el fichero de access solo es necesario para la modalidad "online"
					"${DIR_ROOT}/${CLASSIFY_SCRIPT}" "${i}" "${uris_totales}" "${OUT_INDEX}"
					imprimirCabecera "${OUT_ATTACKS_INFO}" "${OUT_ATTACKS_INFO_HIDE}" "${OUT_CLEAN}" "${OUT_ATTACKS}"
			;;
			*)
				echo "Opción inválida. Las opciones soportadas son: \"1to1\" o \"multiple\". Se sale..."
				exit 1
			;;
		esac

		#Procedemos a reconstruir la salida
		if [ "${NO_REPEAT}" = "yes" ]; then
			uris_totales_file_original=$(wc -l "${DIR_TMP}/${FILENAME}" | cut -d' ' -f1)
			if [ "${uris_totales_file_original}" -ne "${uris_totales}" ]; then
				printf "\nReconstruyendo ficheros de ${ATTACKS_EXTENSION} y ${CLEAN_EXTENSION}...\n\n"
				./"${REBUILD_OUTPUT}" "${DIR_TMP}/${FILENAME}" "${OUT_ATTACKS_INFO}" "${OUT_ATTACKS}" "${OUT_CLEAN}" "${OUT_ATTACKS_INFO_HIDE}"	#Reconstruye el fichero de salida teniendo en cuenta las repeticiones
			fi
			rm -f "${i}"
			mv "${DIR_TMP}/${FILENAME}" "${DIR_ROOT}/${DIRIN_URI}/"
			rm -f "${DIR_TMP}/${FILENAME}"
		fi
		
		#Copiamos resultados a directorio de resultados
		cp -rf "${PATH_LOG}" "${RESULTADOS}"
		cp -rf "${DIROUT_INDEX}" "${RESULTADOS}"
		cp -rf "${DIROUT_ATTACKS}" "${RESULTADOS}"
		cp -rf "${DIROUT_CLEAN}" "${RESULTADOS}"

		#Una vez hemos terminado de procesar un fichero lo anotamos en el directorio de 'entradas_finalizadas'
		touch "entradas_finalizadas/${FILENAME}"

	done
	#Tras procesar ficheros detenemos la instancia de apache
	[ "${LAUNCH_TYPE}" = "online-local" ] && httpd -f "${FILE_CONFIG_APACHE}" -k stop
else
	. "${IL_SCRIPT}"
fi

