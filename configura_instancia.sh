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

crea_instancia_apache()
{
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
		
}

crea_instancia_nemesida()
{
	calcula_puerto
	
	#Adaptamos fichero de configuración de nginx
	sed -i -e "s#^load_module.*#load_module ${WAF_MODULE};#g" \
		-e "s#^error_log.*#error_log ${PATH_AUDIT_LOG} warn;#g" \
		-e "s#^pid.*#pid ${FILE_PID};#g" \
		-e "s#access_log.*main;#access_log ${PATH_ACCESS_LOG}  main;#g" \
		-e "s#include.*conf.d#include ${DIR_NEMESIDA_ONLINE}conf.d#g" \
		-e "s#include.*nwaf#include ${DIR_NEMESIDA_ONLINE}nwaf#g" "${FILE_CONFIG_NEMESIDA}"

	#Adaptamos fichero 'default.conf' de nginx
	sed -i -e "s#listen .*# listen ${DEFAULT_PORT};#g" \
		-e "s#root .*#root ${DIR_NEMESIDA_ONLINE}html;#g" "${FILE_DEFAULT}"

	#Adaptamos 'nwaf.conf' 
	sed -i "s#^nwaf_rules .*#nwaf_rules ${DIR_NEMESIDA_ONLINE}nwaf/rules.bin;#g" "${FILE_NWAF}"

	#Cambiamos en la configuración el puerto de escucha predeterminado por el usado realmente
	sed  -i "s/^DEFAULT_PORT=.*/DEFAULT_PORT=${DEFAULT_PORT}/g" ./framework_config_interna.sh

	#Procedemos a arrancar la instancia nginx
	nginx -c "${FILE_CONFIG_NEMESIDA}"

	if [ $? -eq 0 ]; then 
		printf "Fecha: %s\n" "$(date)" >> "${FILE_FRAMEWORK_LOG}"
		printf "El puerto de escucha de nginx es: %s\n" "${DEFAULT_PORT}" >> "${FILE_FRAMEWORK_LOG}"
	fi 
}



###Main#######

if [ "${MODSECURITY_ONLINE}" -eq 1 ]; then
	crea_instancia_apache
elif [ "${NEMESIDA_ONLINE}" -eq 1 ]; then
	crea_instancia_nemesida
fi



