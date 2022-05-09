#!/bin/sh

#### Cargar configuracion
if [ -f "/opt/integrador/config.sh" ]; then
	. /opt/integrador/config.sh	#IMPORTANTE: La ruta del fichero de configuración debe establecerse a mano en cada uno de los scripts
else
	printf "no existe el fichero de configuración \n"
fi

uri="$1"

#LD_LIBRARY_PATH="/usr/local/modsecurity/lib"
#export LD_LIBRARY_PATH
#gcc -Wall MLAv3_launcher.c -o MLAv3_launcher.out -I/usr/local/modsecurity/include -L/usr/local/modsecurity/lib -lmodsecurity #Compilamos el lanzador de uris basado en libmodsecurity
#chmod 777 MLAv3_launcher.out # otorgamos permiso al ejecutable generado
"${DIR_ROOT}/MLAv3_launcher.out" "${uri}"

