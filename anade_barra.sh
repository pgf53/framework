#!/bin/sh

#Recorre los ficheros de directorio de entrada
#y hace que todas las líneas comiencen por carácter '/'
#Autodetección del formato de entrada

DIRECTORIO_ENTRADA="$1"

for i in "${DIRECTORIO_ENTRADA}"* ; do
	while IFS= read -r uri
	do
		var=$(printf "%s" "${uri}" | grep -P '\t')
		var=$?
		if [ "${var}" -eq 0 ]; then 
			sed -i "s#\t#\t/#g" "${i}"
			sed -i 's#\t//#\t/#g' "${i}"
		elif [ "${var}" -eq 1 ]; then 
			sed -i 's#^#/#g' "${i}"
			sed -i 's#^//#/#g' "${i}"
		fi
		break	#Se analiza solo una, se entiende que todas presentan el mismo formato.
	done < "${i}"
done
