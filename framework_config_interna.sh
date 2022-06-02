#Variables a configurar para el lanzamiento y análisis de las uris
#No se recomienda ejecutar cambios salvo que necesiten hacerse
#Modificaciones en el programa

#DIRECTORIOS. Directorios necesarios para el funcionamiento de la herramienta.

DIR_ROOT="/opt/framework"
DIR_REMOTE="/opt"	#Usado en online-remoto. Directorio de trabajo de equipo remoto donde se desplegarán los scripts de monitorización
DIR_TMP="/tmp"	#Fichero de trabajo temporal. Usado en tiempo de ejecución para almacenar temporalmente ciertos resultados.
DIR_TMP_FAST="/dev/shm"	#Igual que DIR_TMP pero usado en el almacenamiento de resultados más pequeños. El almacenarlos en memoria permite una mayor eficiencia en la ejecución.
DIRIN_URI="01-Uri"	#Directorio con los ficheros de uris.
PATH_LOG="02-Log"	#Directorio con los Logs de los ficheros analizados.
DIROUT_INDEX="03-Index"	#Directorio donde se almacena el fichero resumen del procesado del log.
DIROUT_ATTACKS="04A-Attacks"	#Directorio donde se almacenan los ficheros con las uris detectadas como ataque.
DIROUT_CLEAN="04B-Clean"	#Directorio donde se almacenan los ficheros con las uris detectadas como limpias.
DIR_DETECTORES="${DIR_ROOT}/detectores/"	#Directorio que contiene los detectores integrados por la herramienta framework
DIR_FRAMEWORK_LOG="${DIR_ROOT}/framework_log/"	#Directorio con información sobre la ejecución de framework e.g. puerto de escucha de apache
#Directorios para Cloud
RESULTADOS="Resultados/"	#Directorio donde se almacenarán los resultados una vez finalizado el análisis de un fichero.
#DIR_CLOUD="/opt/06-Cloud_Tareas/framework/02-Recoger_Tarea/Resultados"	#Directorio Cloud de resultados
#RESULTADOS_COMPRIMIDOS="${DIR_CLOUD}/Comprimidos"	#Directorio en Cloud donde se envían los resultados

#FICHERO DE LOG DE FRAMEWORK
FILE_FRAMEWORK_LOG="${DIR_FRAMEWORK_LOG}framework.log"

#DETECTORES DISPONIBLES
#Poner a 1 el detector a usar, el resto debe estar a 0
MODSECURITY_ONLINE=0
MODSECURITY_OFFLINE=0
NEMESIDA_ONLINE=0
IL_MODSECURITY=0
IL_NEMESIDA=1
IL_SNORT=0

#RUTA DETECTORES
DIR_APACHE_ONLINE="${DIR_DETECTORES}apache_online_local/"
DIR_MODSECURITY_OFFLINE="${DIR_DETECTORES}mod_security_offline/"
DIR_NEMESIDA_ONLINE="${DIR_DETECTORES}nemesida_online_local/"
DIR_IL="${DIR_DETECTORES}IL/"

#FICHEROS Y DIRECTORIOS USADOS POR DETECTORES

#MODSECURITY_OFFLINE
DIR_LIB_MODSECURITY_OFFLINE="/usr/lib64"

#APACHE_ONLINE
FILE_CONFIG_APACHE="${DIR_APACHE_ONLINE}conf/httpd.conf"
FILE_CONFIG_SSL="${DIR_APACHE_ONLINE}conf.d/ssl.conf"

#NEMESIDA_ONLINE
FILE_CONFIG_NEMESIDA="${DIR_NEMESIDA_ONLINE}nginx.conf"
WAF_MODULE="${DIR_NEMESIDA_ONLINE}ngx_http_waf_module.so"
FILE_PID="${DIR_NEMESIDA_ONLINE}run/nginx.pid"
FILE_DEFAULT="${DIR_NEMESIDA_ONLINE}conf.d/default.conf"
FILE_NWAF="${DIR_NEMESIDA_ONLINE}nwaf/conf/global/nwaf.conf"

#IL_OFFLINE
DIR_LIB_IL_OFFLINE="/usr/lib64"
SNORT_RULES="${DIR_IL}snort_rules/"
NEMESIDA_RULES="${DIR_IL}nemesida-rules-bin-20220109.txt"
MODSECURITY_RULES="${DIR_IL}etc/basic_rules.conf"

#COLUMNAS OPCIONALES. #Columnas opcionales del fichero de resultados "*-info.attacks". Se generará un nuevo fichero "*-info_hide.attacks" que eliminará estos campos de los resultados.
OPTIONAL_COLUMNS="3 4"


if [ "${MODSECURITY_OFFLINE}" -eq 1 ]; then
	PATH_AUDIT_LOG="${DIR_MODSECURITY_OFFLINE}logs/modsec_audit.log"
	LAUNCH_TYPE="offline" #TIPO DE LANZAMIENTO. "online-local": lanza las uris contra detector ubicado en equipo local. "online-remoto": lanza las uris contra detector ubicado en equipo remoto. "offline": lanza las uris contra 	equipo local, no requiere la presencia de un servidor.
	HIDE_COLUMNS="yes" #HABILITAR/DESHABILITAR COLUMNA. "yes" se ocultan las columnas opcionales. "no" se muestran todas las columnas de fichero "*-info.attacks"
elif [ "${MODSECURITY_ONLINE}" -eq 1 ]; then
	PATH_ACCESS_LOG="${DIR_APACHE_ONLINE}logs/access_log"
	PATH_AUDIT_LOG="${DIR_APACHE_ONLINE}logs/modsec_audit.log"
	LAUNCH_TYPE="online-local"
	HIDE_COLUMNS="yes"
elif [ "${NEMESIDA_ONLINE}" -eq 1 ]; then
	PATH_ACCESS_LOG="${DIR_NEMESIDA_ONLINE}log/access.log"
	PATH_AUDIT_LOG="${DIR_NEMESIDA_ONLINE}log/error.log"
	LAUNCH_TYPE="online-local"
	HIDE_COLUMNS="no"
elif [ "${IL_MODSECURITY}" -eq 1 -o "${IL_NEMESIDA}" -eq 1 -o "${IL_SNORT}" -eq 1 ]; then
	LAUNCH_TYPE="offline"
	HIDE_COLUMNS="no"
fi

#SCRIPTS

#Scripts principales. Scripts cuya ejecución secuencial constituyen la funcionalidad de la herramienta.
LAUNCHER_SCRIPT="1-Launcher.sh"	#Script que lanzará contra un equipo determinado las uris presentes en el fichero de entrada.
if [ "${MODSECURITY_OFFLINE}" -eq 1 -o "${MODSECURITY_ONLINE}" -eq 1 ]; then
	ANALYZER_SCRIPT="2-analyzer.py"	#Script de analizador de Log (introducido por el usuario) que generará el resumen de los ataques (".index") como resultado de procesar el log.
elif [ "${NEMESIDA_ONLINE}" -eq 1 ]; then
	ANALYZER_SCRIPT="2-analyzer_nemesida_online.py"
fi
CLASSIFY_SCRIPT="3-classify.py"	#Script que genera resumen final del análisis. Recibe como entrada el fichero de entrada y el fichero ".index" generado por el ANALYZER_SCRIPT.
IL_SCRIPT="IL.sh"	#Script para dar soporte a IL
CLASSIFY_IL_SCRIPT="3-classify_IL.py"	#Script que genera resumen final del análisis cuando se usa IL.

#Scripts externos. Scripts integrados en la herramienta que permiten funcionalidades adicionales de esta.
NO_REPEAT_SCRIPT="remove_repeats.sh"	#Script usado para eliminar uris repetidas del fichero de entrada. En caso de que el formato de entrada sea "extended" solo se evaluará el campo de "uri"
										#Para catalogar una línea como repetida (se omite el campo ID en la comparación).
REBUILD_OUTPUT="rebuild_output.sh"	#Script de reconstrucción de la salida
ANADE_BARRA="anade_barra.sh"	#Asegura que todas las uris de fichero de entrada empiecen por '/'
CONFIGURA_INSTANCIA="configura_instancia.sh"	#Script utilizado para configurar servidor apache
DETENER_SERVIDOR_INSTANCIA="detener_servidor_instancia.sh"	#Script utilizado para detener los servidores instanciados


#Scripts online-remoto. Scripts utilizados en el tipo de lanzamiento "online-remoto" que permiten la comunicación entre el equipo local y el remoto.
REMOTE_SCRIPT="remoto.sh"	#Utilizado en LAUNCH_MODE=1to1. Script desplegado en equipo remoto que iniciará una sesión byobu y ejecutará REMOTE_MONITORIZATION_SCRIPT.
REMOTE_MULTIPLE_SCRIPT="remoto-multiple.sh"	#Utilizado en LAUNCH_MODE=multiple. Script desplegado en equipo remoto que iniciará una sesión byobu y ejecutará SEND_LOG_SCRIPT.
SEND_LOG_SCRIPT="sendlogs.sh"	#Script utilizado en LAUNCH_MODE=multiple y LAUNCH_TYPE=online_remoto. Envía el log registrado de las uris lanzadas del equipo remoto al equipo local.

#Scripts de monitorización. Scripts utlizados en LAUNCH_MODE=1to1 para detener la ejecución del programa hasta la aparición de ciertos eventos.
LOCAL_MONITORIZATION_SCRIPT="monitoriza-local.sh"	#Script utilizado en LAUNCH_TYPE=online_local. Sirve para monitorizar el acceso de las uris al servidor.
REMOTE_MONITORIZATION_SCRIPT="monitoriza-remoto.sh"	#Script utilizado en LAUNCH_TYPE=online_remoto. Sirve para monitorizar el acceso de las uris a un servidor ubicado en un equipo remoto.

#EXTENSIONES

FILE_IN_EXTENSION=".uri"	#Extensión del fichero de entrada que contiene las uris.
LOG_EXTENSION=".log"	#Extensión del fichero "log" generado por el detector empleado.
INDEX_EXTENTION=".index"	#Extensión del fichero resumen generado por el "analizador" como resultado de procesar el log.
INFO_ATTACKS_EXTENSION="-info.attacks"	#Extensión del fichero de ataques más detallado, generado como resultado de procesar el "index" y el fichero de entrada con las uris lanzadas.
INFO_ATTACKS_HIDE_EXTENSION="-info-hide.attacks"	#Mismo fichero que "-info.attacks" pero eliminando los campos seleccionados por el usuario.
ATTACKS_EXTENSION=".attacks"	#Fichero con las uris detectadas como ataque. Formato: Packet/ID	URI
CLEAN_EXTENSION=".clean"	#Fichero con las uris detectadas como limpias. Formato: Packet/ID	URI


#PATRONES DE BÚSQUEDA

URI_START="Uri ["	#Patrón de inicio para obtener la uri del fichero de "index" generado por ANALYZER_SCRIPT.
URI_END="]"	#Patrón de fin para obtener la uri del fichero de "index" generado por ANALYZER_SCRIPT.
TIME_START="TimeStamp ["	#Patrón de inicio para obtener el TimeStamp del fichero de "index" generado por ANALYZER_SCRIPT.
TIME_END="]"	#Patrón de fin para obtener el TimeStamp del fichero de "index" generado por ANALYZER_SCRIPT.
PACKET="Packet"	#Identificador que precederá al campo "uri" cuando el formato de entrada es "basic". Se usará la posición que ocupa la uri en el fichero de entrada como el "número de paquete".
				#Formato Packet [x]	Uri
ID="ID"	##Identificador que precederá al campo "uri" cuando el formato de entrada es "extended". El id es único para URI. Formato: ID [x]	Uri


#LAUNCHER
SERVERURL_LOCAL="http://localhost"	#URL para lanzamiento local (permite especificar "http" o "https"). Usado en tipo de lanzamiento "online-local" y "offline"


#Prefijo utilizado en la creación de nombres de ficheros en memoria para evitar duplicidades
NOMBRE_RAIZ=$(pwd)
NOMBRE_RAIZ=$(basename "${NOMBRE_RAIZ}")

#BYOBU_SESSION. Nombre de la sesión byobu en la que trabajaremos. IMPORTANTE: este nombre también se usa en la sesión byobu creada en lanzamiento de tipo "online_local"
BYOBU_SESSION="${NOMBRE_RAIZ}_modo_online"

#Puerto por defecto usado en 'multi-instancia online'
DEFAULT_PORT=80
