#!/bin/sh

#### Cargar configuracion
	. ./framework_config.sh
	. ./framework_config_interna.sh


#Recibe como argumento la uri que se desea enviar

FILE_URI="$1" #fichero uri a lanzar

case "${LAUNCH_TYPE}" in
	online-local)
		case "${URIS_FORMAT}" in
			basic)
				URI=$(printf "%s" "${URI}" | sed -e 's/\[/\\[/g' -e 's/\]/\\]/g' -e 's/{/\\{/g' -e 's/}/\\}/g' -e 's/#/%23/g' -e 's/ /%20/g')	#Escape y codificación de caracteres
			;;
			extended)
				URI=$(printf "%s" "${URI}" | cut -d'	' -f2 | sed -e 's/\[/\\[/g' -e 's/\]/\\]/g' -e 's/{/\\{/g' -e 's/}/\\}/g' -e 's/#/%23/g' -e 's/ /%20/g')	#Se extrae la URI en el formato extendido y 																																									se procede como en el 'basic'
			;;
			*)
				printf "\nURIS_FORMAT inválido. Las opciones soportadas son \"basic\" o \"extended\". Se sale...\n"
				exit 1
			;;
		esac
		curl "${SERVERURL_LOCAL}${URI}"  >/dev/null  2>&1	#Se envía la uri al equipo receptor.
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
		LD_LIBRARY_PATH="/usr/local/modsecurity/lib"
		export LD_LIBRARY_PATH
		[ "${URIS_FORMAT}" = "basic" ] && "${DIR_ROOT}/${API_SCRIPT}" "${FILE_URI}" > /dev/null || "${DIR_ROOT}/${API_SCRIPT}" "${FILE_NAME}" > /dev/null	#Script de lanzamiento del usuario. Recibe como argumento el fichero uri de entrada
		[ "${URIS_FORMAT}" = "extended" ] && rm -f "${FILE_NAME}"
	;;
	*)
		echo "LAUNCH_TYPE inválido. Las opciones soportadas son: \"online-local\", \"online-remoto\" u \"offline\". Se sale..."
		exit 1
	;;
esac


