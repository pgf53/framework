#Variables a configurar para el lanzamiento y análisis de las uris

############OPTIONS#########
#En este apartado se dispondrán todas aquellas opciones que alteran las condiciones del lanzamiento 
#y/o la forma en la que se presentarán los resultados.

#MODO DE LANZAMIENTO. "1to1": para lanzamiento y análisis 1 a 1 de las uris. "multiple": para lanzamiento y procesado múltiple de las uris.
LAUNCH_MODE="multiple"

#TIPO DE LANZAMIENTO. "online-local": lanza las uris contra detector ubicado en equipo local. "online-remoto": lanza las uris contra detector ubicado en equipo remoto. "offline": lanza las uris contra 	equipo local, no requiere la presencia de un servidor. 
LAUNCH_TYPE="offline"

#REPETICIONES EN FICHERO DE ENTRADA. "yes" elimina las uris repetidas en el fichero de entrada y posteriormente recontruye la salida para obtener el mismo resultado que si se lanzase el fichero de entrada original. Se realiza con el propósito de acelerar el anális omitiendo uris repetidas. "no" envía fichero uri de entrada original (con repeticiones si las hubiere).
NO_REPEAT="no"

#SSHPASS. "yes": habilita el uso de sshpass. "no": deshabilita el uso de sshpass (se usará ssh y scp en las conexiones remotas).
SSH_PASS="yes"
#PASS. Contraseña de equipo remoto. Necesario si se emplea sshpass.
PASS="root"

#CLOUD. configuración para cuando se ejecuta la herramienta con Cloud.
#EJECUCIÓN EN CLOUD. "yes" prepara directorio con los resultados del análisis y los transfiere al equipo origen. "no" Los archivos de resultados son almacenados en equipo local
#CLOUD_EXECUTION="yes"
#EQUIPO ORIGEN CLOUD. Dirección ip del equipo emisor de la herramienta en cloud. Se usa para transferir los resulados automáticamente una vez finaliza el análisis.
#SOURCE_DEVICE="lt04"

#Usuario y contraseña para conectarnos a equipo origen de cloud. Usado en SSHPASS.
#USER_CLOUD="root"
#PASS_CLOUD="root"

#FORMATO DE FICHERO URI DE ENTRADA.	"basic": URI
									#"extended": ID	URI
URIS_FORMAT="basic"

#COLUMNAS OPCIONALES. #Columnas opcionales del fichero de resultados "*-info.attacks". Se generará un nuevo fichero "*-info_hide.attacks" que eliminará estos campos de los resultados.
OPTIONAL_COLUMNS="3 4"

#HABILITAR/DESHABILITAR COLUMNA. "yes" se ocultan las columnas opcionales. "no" se muestran todas las columnas de fichero "*-info.attacks"
HIDE_COLUMNS="yes"


############LAUNCHER#########
#En este apartado se configurarán las variables relativas al lanzador.

#Utilizado en tipo "offline". Ruta del script con la API de lanzamiento introducido por el usuario.
API_SCRIPT="MLAv3_launcher.out"



############ONLINE_REMOTO#########
#En este apartado se configurarán las variables necesarias para el establecimiento de la conexión y transferencia de archivos con el equipo remoto.

#IP_LOCAL. Dirección IP del equipo local. No puede establecerse como "localhost". Es usada por el equipo remoto para transerir archivos a equipo local
IP_EQUIPO_LOCAL="172.16.17.1"

#IP_REMOTA. IP del equipo remoto al que nos conectaremos. IMPORTANTE: "IP_REMOTE" no tiene por qué coincidir con la ip presente en "SERVERURL". Caso de detector como equipo intermedio
IP_REMOTE="172.16.17.2"

#USUARIO_REMOTO. Usuario con el que accederemos a equipo remoto
USER_REMOTE="root"

#IP del servidor contra la que se harán los lanzamientos. Necesario para tipo de lanzamiento "online-remoto".
SERVERURL="http://lt05"
