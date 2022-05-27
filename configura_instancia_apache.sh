#!/bin/sh

#### Cargar configuracion
. ./framework_config.sh
. ./framework_config_interna.sh

#Obtiene en variable 'DEFAULT_PORT' un puerto disponible
calcula_puerto()
{
	while true; do
		[ "$(nmap -p "${DEFAULT_PORT}" localhost | grep closed)" ] && break || DEFAULT_PORT=$((DEFAULT_PORT+1))
	done
}


###Main#######
calcula_puerto

#Adaptamos fichero de configuración de apache
sed -i "s#^ServerRoot .*#ServerRoot \"${DIR_APACHE_ONLINE}\"#g" "${FILE_CONFIG_APACHE}"	#Establecemos el serverRoot
sed -i "s/^Listen .*/Listen ${DEFAULT_PORT}/g" "${FILE_CONFIG_APACHE}"	#Establecemos puerto de escucha 

printf "Fecha: %s\n" "$(date)" >> "${FILE_FRAMEWORK_LOG}"
printf "El puerto de escucha de apache es: %s\n" "${DEFAULT_PORT}" >> "${FILE_FRAMEWORK_LOG}"

#Cambiamos en la configuración el puerto de escucha predeterminado por el usado realmente
sed  -i "s/^DEFAULT_PORT=.*/DEFAULT_PORT=${DEFAULT_PORT}/g" ./framework_config_interna.sh

#Establecemos puerto HTTPS
DEFAULT_PORT=$((DEFAULT_PORT+1))
calcula_puerto

#Adaptamos ssl.conf
sed -i "s/^Listen .*/Listen ${DEFAULT_PORT} https/g" "${FILE_CONFIG_SSL}"
sed -i "s/^<VirtualHost _default_:.*/<VirtualHost _default_:${DEFAULT_PORT}>/g" "${FILE_CONFIG_SSL}"

#Procedemos a arrancar el servidor
httpd -f "${FILE_CONFIG_APACHE}" -k start
