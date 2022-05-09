#!/bin/sh

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
	if [ "${HIDE_COLUMNS}" = "yes" ]; then
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
	sed -i "1i$IMPRIMIR3"  "${OUT_ATTACKS_INFO}"
	sed -i "1i$IMPRIMIR2"  "${OUT_ATTACKS_INFO}"
	sed -i "1i$IMPRIMIR1"  "${OUT_ATTACKS_INFO}"

	#Imprimimos cabecera en fichero "*-info_hide.attacks" si existe
	if [ -f "${OUT_ATTACKS_INFO_HIDE}" ]; then
		sed -i "1i$IMPRIMIR3"  "${OUT_ATTACKS_INFO_HIDE}"
		sed -i "1i$IMPRIMIR2"  "${OUT_ATTACKS_INFO_HIDE}"
		sed -i "1i$IMPRIMIR1"  "${OUT_ATTACKS_INFO_HIDE}"
	fi
}


#Entradas
FILE_IN="$1"
FILE_INFO_ATTACKS="$2"
FILE_ATTACKS="$3"
FILE_CLEAN="$4"
FILE_INFO_ATTACKS_HIDE="$5"

#Salidas
#Son salidas temporales que para poder sobreescribir archivos finales, la extensión no es relevante
FILE_INFO_ATTACKS_RECONSTRUIDO="${DIR_ROOT}/$(basename ${FILE_INFO_ATTACKS%.*})-reconstruido.attacks"	#Fichero de salida
FILE_ATTACKS_RECONSTRUIDO="${DIR_ROOT}/$(basename ${FILE_ATTACKS%.*})-reconstruido.attacks"	#Fichero de salida
FILE_CLEAN_RECONSTRUIDO="${DIR_ROOT}/$(basename ${FILE_CLEAN%.*})-reconstruido.clean"	#Fichero de salida
FILE_INFO_ATTACKS_RECONSTRUIDO_HIDE="${DIR_ROOT}/$(basename ${FILE_INFO_ATTACKS%.*})-reconstruido_hide.attacks"	#Fichero de salida
#Preparamos 
rm -f "${FILE_INFO_ATTACKS_RECONSTRUIDO}" ${FILE_ATTACKS_RECONSTRUIDO} "${FILE_CLEAN_RECONSTRUIDO}" "${FILE_INFO_ATTACKS_RECONSTRUIDO_HIDE}"

uri_actual=1
uris_totales=$(wc -l "${FILE_IN}" | cut -d' ' -f1)

while IFS= read -r input
do
	printf "\r                                          "
	printf "\r(%s/%s)"  "${uri_actual}"  "${uris_totales}"

	if [ "${URIS_FORMAT}" = "basic" ]; then
		packet="${PACKET} [${uri_actual}]"
		export input
		#Buscamos en el fichero de '-info.attacks' la línea que contenga la uri del fichero de entrada
		#Usamos export para cargar la varible como una variable de entorno en awk y así evitar ciertas
		#interpretaciones de caracteres
		line_file_attacks=$(awk -F'\t' -v OFS='\t' '{ if ($2==ENVIRON["input"]) print}' "${FILE_INFO_ATTACKS}")
		if [ "${line_file_attacks}" = "" ]; then	#Si no se encuentra es una uri "clean"
			printf "%s	%s" "${packet}" "${input}" >> "${FILE_CLEAN_RECONSTRUIDO}"
			printf \\n  		 >> "${FILE_CLEAN_RECONSTRUIDO}"
		else	#Es ataque
			line_file_attacks=$(printf "%s" "${line_file_attacks}" | awk -F'\t' -v OFS='\t' -v packet="${packet}" '{$1 = packet; print $0}')	#Añade número de paquete
			printf "%s" "${line_file_attacks}" >> "${FILE_INFO_ATTACKS_RECONSTRUIDO}"
			printf \\n  		 				>> "${FILE_INFO_ATTACKS_RECONSTRUIDO}"
			printf "%s	%s" "${packet}" "${input}" >> "${FILE_ATTACKS_RECONSTRUIDO}"
			printf \\n  		 				>> "${FILE_ATTACKS_RECONSTRUIDO}"
		fi
	elif [ "${URIS_FORMAT}" = "extended" ]; then
		uri=$(printf "%s" "${input}" | cut -d'	' -f2)
		id_number=$(printf "%s" "${input}" | cut -d'	' -f1)
		identificador="${ID} [${id_number}]"
		line_file_attacks=$(awk -F'\t' -v OFS='\t' -v uri="${uri}" '{ if ($2==uri) print}' "${FILE_INFO_ATTACKS}")
		if [ "${line_file_attacks}" = "" ]; then	#Es una uri "clean"
			printf "%s	%s" "${identificador}" "${uri}" >> "${FILE_CLEAN_RECONSTRUIDO}"
			printf \\n  		 >> "${FILE_CLEAN_RECONSTRUIDO}"
		else	#Es ataque
			line_file_attacks=$(printf "%s" "${line_file_attacks}" | awk -F'\t' -v OFS='\t' -v identificador="${identificador}" '{$1 = identificador; print $0}')
			printf "%s" "${line_file_attacks}" >> "${FILE_INFO_ATTACKS_RECONSTRUIDO}"
			printf \\n  		 				>> "${FILE_INFO_ATTACKS_RECONSTRUIDO}"
			printf "%s	%s" "${identificador}" "${uri}" >> "${FILE_ATTACKS_RECONSTRUIDO}"
			printf \\n  		 				>> "${FILE_ATTACKS_RECONSTRUIDO}"
		fi
	fi
	uri_actual=$((uri_actual+1))	#Incrementamos contador de lectura
done < "${FILE_IN}"

imprimirCabecera "${FILE_INFO_ATTACKS_RECONSTRUIDO}" "${FILE_INFO_ATTACKS_RECONSTRUIDO_HIDE}" "${FILE_CLEAN_RECONSTRUIDO}" "${FILE_ATTACKS_RECONSTRUIDO}"

rm -f "${FILE_INFO_ATTACKS}" "${FILE_ATTACKS}" "${FILE_CLEAN}" "${FILE_INFO_ATTACKS_HIDE}"

mv "${FILE_INFO_ATTACKS_RECONSTRUIDO}" "${FILE_INFO_ATTACKS}"
mv "${FILE_INFO_ATTACKS_RECONSTRUIDO_HIDE}" "${FILE_INFO_ATTACKS_HIDE}"
mv "${FILE_ATTACKS_RECONSTRUIDO}" "${FILE_ATTACKS}"
mv "${FILE_CLEAN_RECONSTRUIDO}" "${FILE_CLEAN}"
