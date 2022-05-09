#!/bin/sh

#Elimina líneas repetidas de fichero ".uri" de entrada

#Entradas
FILE_IN="$1"
FORMAT="$2"
DIR_ROOT="$3"

#Salidas
FILE_IN_NORMALIZED="${DIR_ROOT}/$(basename ${FILE_IN%.*})-normalizado.uri"

if [ "${FORMAT}" == "basic" ]; then
	awk '!seen[$0]++' "${FILE_IN}" > "${FILE_IN_NORMALIZED}"
	rm -f "${FILE_IN}"
	mv "${FILE_IN_NORMALIZED}" "${FILE_IN}"
elif [ "${FORMAT}" == "extended" ]; then
	awk -F'\t' '!seen[$2]++' "${FILE_IN}" > "${FILE_IN_NORMALIZED}"
	rm -f "${FILE_IN}"
	mv "${FILE_IN_NORMALIZED}" "${FILE_IN}"
fi
