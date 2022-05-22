#!/bin/sh

#### Cargar configuracion
. ./framework_config.sh
. ./framework_config_interna.sh

#funciones

#clasifica los resultados de inspector log para la modalidad múltiple
#Recibe fichero de entrada y obtenido por IL y los compara para
#extraer los ataques y las limpias en el formato habitual.
clasifica_multiple()
{
	if [ ${URIS_FORMAT} = "basic" ]; then
		while IFS= read -r line_uri
		do
			while IFS= read -r line_attack
			do
				if [ "${line_uri}" = "${line_attack}" ]; then
					#Escribimos
				fi
			done < "$2"
		done < "$1"
	fi
}


#################Multiple-basic####################
if [ ${URIS_FORMAT} = "basic" -a ${LAUNCH_MODE} = "multiple" ]; then
	#############IL-ModSecurity##################
	if [ "${IL_MODSECURITY}" -eq 1 ]; then
		LD_LIBRARY_PATH="/usr/local/modsecurity/lib"
		export LD_LIBRARY_PATH
		for i in "${DIR_ROOT}/${DIRIN_URI}/"* ; do
			NOMBRE_FICHERO=$(basename "${i}" | sed "s/${FILE_IN_EXTENSION}//g")
			IL/ms-inspectorlog -l "${i}" -t list -r etc/basic_rules.conf > "${NOMBRE_FICHERO}${ATTACKS_EXTENSION}"
			#Eliminamos cabecera y resumen
			LINEAS_FICHERO=$(wc -l "${NOMBRE_FICHERO}${ATTACKS_EXTENSION}" | cut -d' ' -f'1')
			tail -$((LINEAS_FICHERO-3)) "${i}" | tail -$((LINEAS_FICHERO-3)) | head -$((LINEAS_FICHERO-4)) > "${NOMBRE_FICHERO}_sin_cabeceras${ATTACKS_EXTENSION}"
			clasifica_multiple "${i}" "${NOMBRE_FICHERO}_sin_cabeceras${ATTACKS_EXTENSION}"
		done

	#############IL-Nemesida##################
	elif [ "${IL_NEMESIDA}" -eq 1 ]; then
		for i in "${DIR_ROOT}/${DIRIN_URI}/"* ; do
			./ms-inspectorlog -l "${i}" -t list -r etc/basic_rules.conf
		done


	#############IL-Snort##################
	elif [ "${IL_SNORT}" -eq 1 ]; then
		for i in "${DIR_ROOT}/${DIRIN_URI}/"* ; do
			./ms-inspectorlog -l "${i}" -t list -r etc/basic_rules.conf
		done
	fi

#################Multiple-extended####################
#elif [ ${URIS_FORMAT} = "extended" -a ${LAUNCH_MODE} = "multiple" ]; then


#################1to1-basic####################
#elif [ ${URIS_FORMAT} = "basic" -a ${LAUNCH_MODE} = "1to1" ]; then

#################1to1-extended####################
#elif [ ${URIS_FORMAT} = "extended" -a ${LAUNCH_MODE} = "1to1" ]; then


fi
