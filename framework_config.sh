#Variables a configurar para el lanzamiento y análisis de las uris

############OPTIONS#########
#En este apartado se dispondrán todas aquellas opciones que alteran las condiciones del lanzamiento 
#y/o la forma en la que se presentarán los resultados.

#MODO DE LANZAMIENTO. "1to1": para lanzamiento y análisis 1 a 1 de las uris. "multiple": para lanzamiento y procesado múltiple de las uris.
LAUNCH_MODE="1to1"

#REPETICIONES EN FICHERO DE ENTRADA. "yes" elimina las uris repetidas en el fichero de entrada y posteriormente recontruye la salida para obtener el mismo resultado que si se lanzase el fichero de entrada original. Se realiza con el propósito de acelerar el anális omitiendo uris repetidas. "no" envía fichero uri de entrada original (con repeticiones si las hubiere).
NO_REPEAT="no"


#FORMATO DE FICHERO URI DE ENTRADA.	"basic": URI
									#"extended": ID	URI
URIS_FORMAT="basic"


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

#SSHPASS. "yes": habilita el uso de sshpass. "no": deshabilita el uso de sshpass (se usará ssh y scp en las conexiones remotas).
SSH_PASS="yes"
#PASS. Contraseña de equipo remoto. Necesario si se emplea sshpass.
PASS="root"
