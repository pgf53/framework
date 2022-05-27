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

#SCRIPTS

#Scripts principales. Scripts cuya ejecución secuencial constituyen la funcionalidad de la herramienta.
LAUNCHER_SCRIPT="1-Launcher.sh"	#Script que lanzará contra un equipo determinado las uris presentes en el fichero de entrada.
ANALYZER_SCRIPT="2-analyzer.py"	#Script de analizador de Log (introducido por el usuario) que generará el resumen de los ataques (".index") como resultado de procesar el log.
CLASSIFY_SCRIPT="3-classify.py"	#Script que genera resumen final del análisis. Recibe como entrada el fichero de entrada y el fichero ".index" generado por el ANALYZER_SCRIPT.

#Scripts externos. Scripts integrados en la herramienta que permiten funcionalidades adicionales de esta.
NO_REPEAT_SCRIPT="remove_repeats.sh"	#Script usado para eliminar uris repetidas del fichero de entrada. En caso de que el formato de entrada sea "extended" solo se evaluará el campo de "uri"
										#Para catalogar una línea como repetida (se omite el campo ID en la comparación).
REBUILD_OUTPUT="rebuild_output.sh"	#Script de reconstrucción de la salida
ANADE_BARRA="anade_barra.sh"	#Asegura que todas las uris de fichero de entrada empiecen por '/'
CONFIGURA_INSTANCIA_APACHE="configura_instancia_apache.sh"	#Script utilizado para configurar servidor apache

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


#ACCESS_LOG. Requerido en lanzamiento de tipo "online". Ruta del registro de accesos al servidor. 
PATH_ACCESS_LOG="detectores/apache_online_local/logs/access_log"

#AUDIT_LOG. Ruta del registro de auditoría donde el detector escribe información  (Reglas vulneradas, severidad...) sobre la uri lanzada detectada como ataque.
PATH_AUDIT_LOG="detectores/apache_online_local/logs/modsec_audit.log"	#MLAv2 (online-local)
#PATH_AUDIT_LOG="/var/log/modsec_audit.log"	#MLAv3 (offline)
#PATH_AUDIT_LOG="detectores/mod_security_offline/logs/modsec_audit.log"	#MLAv3 (offline)

#Prefijo utilizado en la creación de nombres de ficheros en memoria para evitar duplicidades
NOMBRE_RAIZ=$(pwd)
NOMBRE_RAIZ=$(basename "${NOMBRE_RAIZ}")

#BYOBU_SESSION. Nombre de la sesión byobu en la que trabajaremos. IMPORTANTE: este nombre también se usa en la sesión byobu creada en lanzamiento de tipo "online_local"
BYOBU_SESSION="${NOMBRE_RAIZ}_modo_online"

#IL
IL_SCRIPT="${DIR_ROOT}/IL.sh"
IL="0"	#'1' para activar ejecución de IL (desactivada por defecto)
IL_MODSECURITY="1"	#'1' para activar IL con ModSecurity '0' para desactivarla (opción por defecto)
IL_NEMESIDA="0"	#'1' para activar IL con Nemesida '0' para desactivarla
IL_SNORT="0"	#'1' para activar IL con Snort '0' para desactivarla

#DETECTORES
DIR_APACHE_ONLINE="${DIR_DETECTORES}apache_online_local/"
FILE_CONFIG_APACHE="${DIR_APACHE_ONLINE}conf/httpd.conf"
FILE_CONFIG_SSL="${DIR_APACHE_ONLINE}conf.d/ssl.conf"

#Puerto por defecto usado en 'multi-instancia online'
DEFAULT_PORT=80
