#!/bin/sh

#Recorre los ficheros de directorio de entrada
#y hace que todas las líneas comiencen por carácter '/'

DIRECTORIO_ENTRADA="$1"

for i in "${DIRECTORIO_ENTRADA}"* ; do
	sed -i 's#^#/#g' "${i}"
	sed -i 's#^//#/#g' "${i}"
done
