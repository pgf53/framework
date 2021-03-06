#!/bin/sh

#### Cargar configuracion
. ./framework_config_interna.conf


#Recibe como argumento la uri que se desea enviar

FILE_URI="$1" #fichero uri a lanzar

case "${LAUNCH_TYPE}" in
	online-local)
		case "${URIS_FORMAT}" in
			basic)
				uri_actual=1
				uris_totales=$(wc -l "${FILE_URI}" | cut -d' ' -f1)
				while IFS= read -r URI	
				do
					URI=$(printf "%s" "${URI}" | sed -e 's/\[/\\[/g' -e 's/\]/\\]/g' -e 's/{/\\{/g' -e 's/}/\\}/g' -e 's/#/%23/g' -e 's/ /%20/g')	#Escape y codificación de caracteres
					curl "${SERVERURL_LOCAL}:${DEFAULT_PORT}${URI}" >/dev/null  2>&1
				if [ ${LAUNCH_MODE} = "multiple" ]; then
					printf "\r                                          "
					printf "\r(%s/%s)"  "${uri_actual}"  "${uris_totales}"
					uri_actual=$((uri_actual+1))	#Incrementamos contador de lectura
					printf "\n"
				fi
				done < "${FILE_URI}"
			;;
			extended)
				uri_actual=1
				uris_totales=$(wc -l "${FILE_URI}" | cut -d' ' -f1)
				while IFS= read -r URI	
				do
					URI=$(printf "%s" "${URI}" | cut -d'	' -f2 | sed -e 's/\[/\\[/g' -e 's/\]/\\]/g' -e 's/{/\\{/g' -e 's/}/\\}/g' -e 's/#/%23/g' -e 's/ /%20/g')
					curl "${SERVERURL_LOCAL}:${DEFAULT_PORT}${URI}" >/dev/null  2>&1
					if [ ${LAUNCH_MODE} = "multiple" ]; then
						printf "\r                                          "
						printf "\r(%s/%s)"  "${uri_actual}"  "${uris_totales}"
						uri_actual=$((uri_actual+1))	#Incrementamos contador de lectura
						printf "\n"
					fi
				done < "${FILE_URI}"
			;;
			*)
				printf "\nURIS_FORMAT inválido. Las opciones soportadas son \"basic\" o \"extended\". Se sale...\n"
				exit 1
			;;
		esac
	;;
	online-remoto)
		case "${URIS_FORMAT}" in
			basic)
				URI=$(printf "%s" "${URI}" | sed -e 's/\[/\\[/g' -e 's/\]/\\]/g' -e 's/{/\\{/g' -e 's/}/\\}/g' -e 's/#/%23/g' -e 's/ /%20/g')
			;;
			extended)
				URI=$(printf "%s" "${URI}" | cut -d'	' -f2 | sed -e 's/\[/\\[/g' -e 's/\]/\\]/g' -e 's/{/\\{/g' -e 's/}/\\}/g' -e 's/#/%23/g' -e 's/ /%20/g')
			;;
			*)
				printf "\nURIS_FORMAT inválido. Las opciones soportadas son \"basic\" o \"extended\". Se sale...\n"
				exit 1
			;;
		esac
		curl "${SERVERURL}${URI}"  >/dev/null  2>&1
	;;
	offline)
			if [ "${URIS_FORMAT}" = "extended" ]; then
				FILE_NAME=$(basename "${FILE_URI}")
				 awk '{print $2}' "${FILE_URI}" > "${FILE_NAME}"
			fi
		#Necesario para ModsecurityV3
		LD_LIBRARY_PATH="${DIR_LIB_MODSECURITY_OFFLINE}"
		export LD_LIBRARY_PATH
		[ "${URIS_FORMAT}" = "basic" ] && "${DIR_ROOT}/${API_SCRIPT}" "${FILE_URI}" > /dev/null || "${DIR_ROOT}/${API_SCRIPT}" "${FILE_NAME}" > /dev/null	#Script de lanzamiento del usuario. Recibe como argumento el fichero uri de entrada
		[ "${URIS_FORMAT}" = "extended" ] && rm -f "${FILE_NAME}"
	;;
	*)
		echo "LAUNCH_TYPE inválido. Las opciones soportadas son: \"online-local\", \"online-remoto\" u \"offline\". Se sale..."
		exit 1
	;;
esac
