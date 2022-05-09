#!/bin/sh

#### Cargar configuracion
	. ./framework_config.sh
	. ./framework_config_interna.sh


### Configuración. Posible carga externa
if [ -f ./MLA.conf ]; then
    ./MLA.conf
else
    # CADENAS IMPRESION EN "fichero.index"
    # 1) Separadores: Corchetes
    Si=" ["
    SiSIN="["
    Sf="]"
    TAB="$(printf \\t)"
    # 2) Textos
    TIMESTAMP_IMP="TimeStamp"
    URI_IMP="Uri"
    PLMin_IMP="PLmin"
    SCORE_IMP="Score"
    NATAQUES_IMP="Nattacks"

    # Ubicacion ficheros de logs de Mod_Security
#    DIR_MODLOG="/var/log/httpd"
#    MODLOG="${DIR_MODLOG}/modsec_audit.log"
#    BCK_MODLOG="${MODLOG}-bck"
	MODLOG="$1"

ID_RULES="${DIR_ROOT}/id_rules"

    # Configuracion CRS
    IDimpresion="1000"			# ID asignado a la regla SecAction que imprime [msg "Incoming Anomaly Score: x"]
    # CONFIGURADO MANUALMENTE En: /etc/httpd/conf.d/mod_security.conf
    # SecAction \
    #   "id:1000,\
    #   phase:5,\
    #   pass,\
    #   t:none,\
    #   log,\
    #   noauditlog,\
    #   msg:'Incoming Anomaly Score: %{TX.ANOMALY_SCORE}'"

    # Para cambiar el Nivel de Paranoia (PL: 1-4) de ModSecurity: 
    #/etc/httpd/owasp-modsecurity-crs/crs-setup.conf
    #SecAction \
    #  "id:900000,\
    #   phase:1,\
    #   nolog,\
    #   pass,\
    #   t:none,\
    #   setvar:tx.executing_paranoia_level=4"

    VERSION_MLA_ANALYZER="1.0"			# Version del programa

fi

# Asumiendo "/etc/logrotate.d/mod_security", en /var/log/httpd/
# se generan: modsec_audit.log, modsec_audit.log.1, modsec_audit.log.2, ...
# (si se configura "compress" serían modsec_audit.log.1.gz, modsec_audit.log.2.gz, ...)
#####



### Lectura de Argumentos y Variables Globales

TIMESTAMP_FILES="$(date +%F-%H%M%S)" 			# Para el nombre del fichero de salida
TMP="/tmp/MLA-${TIMESTAMP_FILES}.tmp"			# Fichero de trabajo temporal

IN="$1"					# Fichero.log de entrada

OUT_INDEX="${DIR_ROOT}/${DIROUT_INDEX}/$(basename ${IN%.*}).index"   #Fichero de salida
					    # Se mantiene mismo nombre que a entrada,
					    #quitando su extension y añadiendo ".index"

# Separadores de Seccion en cada Transaccion de "modsec_audit.log"
SECCIONA="-A--"			# A: Contiene Comienzo y "TimeStamp"
SECCIONB="-B--"			# B: Contiene URL
SECCIONH="-H--"			# H: Contiene "Score" y "id"
SECCIONZ="-Z--"			# Z: Final Transaccion
# Hay mas secciones, pero solo nos interesan estas

# Patrones para buscar datos de interes en "fichero.log" (formato "modsec_audit.log")
# TimeStamp Log
PATRONTimeStampinicio='['
PATRONTimeStampfin=']'

# URI en Log
PATRONURIinicio=' '
PATRONURIfin=' '

# PL minimo
PATRONPLinicio='[tag "paranoia-level/'
PATRONPLfin='"]'

# ID Regla
PATRONIDinicio='[id "'
PATRONIDfin='"]'

# Score Reglas
#ModSecurityV2
#PATRONSCOREinicio='[msg "Incoming Anomaly Score: '
#PATRONSCOREfin='"]'
#ModSecurityV3
PATRONSCOREinicio='[msg "Inbound Anomaly Score Exceeded (Total Score: '
PATRONSCOREfin=')"]'

#####


### Funciones

# Busca la cadena indicada en la linea recibida
# Llamada:	buscarCadena   lineaAnalizada  cadenaBuscada
# Devuelve:	1 (encontrada), 0 (otro caso)
buscarCadena()
{
    lineaAnalizada="$1"
    cadenaBuscada="$2"

    printf "%s" "${lineaAnalizada}" | grep -i -s -F -- "${cadenaBuscada}" 2>&1 1>/dev/null
    # NOTA: Explicacion parametros del grep:
    # + "-i": Insensitive
    # + "-s": Silencioso (no imprime en pantalla)
    # + "-F": Desactiva expresiones regulares. Necesario para poder buscar cadenas como "[11/Jul/2019:12:05:46 +0200]"
    #         (igual para URLs con "?") y que los corchetes NO se interpreten como rangos de caracteres a buscar (sino como carecteres normales)
    # + "--": Desactiva la lectura de argumentos. Hace que el siguiente valor se interprete como la cadena a buscar.
    #         necesario para poder buscar cadenas como "--A-" y que el grep no la tome como un argumento.
    [ $? -eq 0 ] && return 1 || return 0		# Grep devuelve "0" si lo encuentra
}


# Comprueba si existe el patron de inicio en la cadena recibida. En caso afirmativo, extrae
# el fragmento de cadena ubicado entre los dos patrones dados
# Llamada: extraerIntervalo   cadenaAnalizar   patronInicio   patronFin
# Devuelve: Imprime (salida estándar) el fragmento extraido (o cadena vacia si no se encuentra)
extraerIntervalo()
{
    cadenaAnalizar="$1"
    patronInicio="$2"
    patronFin="$3"
    intervaloExtraido=""
    TMP1=""

    buscarCadena   "${cadenaAnalizar}"   "${patronInicio}"
    if [ $? -eq 1 ]; then
	TMP1="${cadenaAnalizar#*${patronInicio}}"		# Elimina texto anterior al primer patronInicio (prefijo)
	printf "%s" "${TMP1%%$patronFin*}"			# Elimina texto tras     el primer patronFin    (sufijo)
    fi
}


# Comprueba si la linea actual es un cambio de seccion de la transaccion
# Llamada:   detectarCambioSeccion   lineaLogAnalizar
# Salida: Si detecta inicio de seccion, imprime la seccion identificada
detectarCambioSeccion()
{
    lineaLogAnalizar="$1"
    for seccion in "${SECCIONA}" "${SECCIONB}" "${SECCIONH}" "${SECCIONZ}"; do

	buscarCadena "${lineaLogAnalizar}" "${seccion}"  	 #2>&1 1>/dev/null
	[ $? -eq 1 ] && echo "${seccion}"
    done 2>/dev/null
}


# Extrae el TimeStampp en Log
# Llamada:  extraerTimestamp  lineaLogAnalizada
# Devuelve: Imprime (salida estándar) Timestamp extraido de la linea (o cadena vacia si no se encuentra)
extraerTimeStamp()
{
    # Lectura de argumentos
    lineaLogAnalizada="$1"

    # Buscar
    printf "%s" "$(extraerIntervalo  "${lineaLogAnalizada}"   "${PATRONTimeStampinicio}"   "${PATRONTimeStampfin}")"
}


# Extrae URI en log
# Llamada:  extraerURI  lineaLogAnalizada
# Devuelve: Imprime (salida estándar) la URI extraido de la linea (o cadena vacia si no se encuentra)
extraerURI()
{
    # Lectura de argumentos
    lineaLogAnalizada="$1"

    # Buscar
    printf "%s" "$(extraerIntervalo  "${lineaLogAnalizada}"   "${PATRONURIinicio}"   "${PATRONURIfin}")"
}



# Extrae el PL minimo de la linea recibida (de la Seccion H del modsec_audit.log)
# Llamada:  extraerPLmin  lineaLogAnalizada
# Devuelve: Imprime (salida estándar) PL extraido de la linea (o cadena vacia si no se encuentra)
extraerPLmin()
{
    # Lectura de argumentos
    lineaLogAnalizada="$1"

    # Buscar
    printf "%s" "$(extraerIntervalo  "${lineaLogAnalizada}"   "${PATRONPLinicio}"   "${PATRONPLfin}")"
}


# Extrae el Score de la linea recibida (de la Seccion H del modsec_audit.log)
# Llamada:  extraerScore  lineaLogAnalizada
# Devuelve: Imprime (salida estándar) el score extraido de la linea (o cadena vacia si no se encuentra)
extraerScore()
{
    # Lectura de argumentos
    lineaLogAnalizada="$1"

    # Buscar
    printf "%s" "$(extraerIntervalo  "${lineaLogAnalizada}"   "${PATRONSCOREinicio}"   "${PATRONSCOREfin}")"
}


# Extrae el ID de regla de la linea recibida (de la Seccion H del modsec_audit.log)
# Llamada:  extraerId  lineaLogAnalizada
# Devuelve: Imprime (salida estándar) el Id de regla extraido de la linea (o cadena vacia si no se encuentra)
extraerId()
{
    # Lectura de argumentos
    lineaLogAnalizada="$1"

    # Buscar
    printf "%s" "$(extraerIntervalo  "${lineaLogAnalizada}"   "${PATRONIDinicio}"   "${PATRONIDfin}")"
}


# Imprime linea de ataque para Indice
# Llamada: imprimirAtaque  timestamp     uri    plminimo     score    numReglas    listaIDsReglas
imprimirAtaqueIndice()
{
    # Lectura de argumentos
    timestampF="$1"
    uriF=$(printf "%s" "$2" | xargs -0)		    		     # Se eliminan posibles espaciados anteriores/posteriores a la URI

    #    NOTA: En "crs-sttup.conf" se indica que ese mensaje sólo se imprime en las reglas
    #	   con PL>=2 (esto es, en las reglas con PL=1 no aparece.
    #	   Consecuentemente, un "PLmin []" vacio equivale a "PLMin [1]" <== ***
    [ "$3" = "" ] && plMinF="1" || plMinF="$3"
    scoreF="$4"
    nreglasF="$5"
    shift 5
    listaIDsReglasF="$*"		# Lista de IDs separados por espacio
    INFO_ATAQUES=""			# Lista IDs reconstruida entre corchetes y tabulacion

    Si=" ["
    Sf="]"
    TAB="$(printf \\t)"
    # 2) Textos
    TIMESTAMP_IMP="TimeStamp"
    URI_IMP="Uri"
    PLMin_IMP="PLmin"
    SCORE_IMP="Score"
    NATAQUES_IMP="Nattacks"

    # Variables de impresion
    TIMESTAMP_LOG="${TIMESTAMP_IMP}${Si}${timestampF}${Sf}"				# TimeStamp Log
    URIATAQUE="${URI_IMP}${Si}${uriF}${Sf}"						# URI de ATAQUE analizada
    PLMin="${PLMin_IMP}${Si}${plMinF}${Sf}"						# PL Minimo con el que se detecta esta URI como ataque
    SCORE="${SCORE_IMP}${Si}${scoreF}${Sf}"						# Anomaly_Score
    NATAQUES="${NATAQUES_IMP}${Si}${nreglasF}${Sf}"					# Num_reglas_aplicadas
    for sid in ${listaIDsReglasF}; do
	INFO_ATAQUES="${INFO_ATAQUES}$( [ -n "${INFO_ATAQUES}" ] && printf \\t)${SiSIN}${sid}${Sf}"	# ID reglas entre corchetes y separados por tabulacion
    done

    # Impresion (tambien puede usarse la variable "${TAB}"
	if [ "${nreglasF}" -ne 0 ]; then	#Si el número de ataques es cero no imprimimos en el index
    printf "%s\t%s\t%s\t%s\t%s\t%s"   "${TIMESTAMP_LOG}"   "${URIATAQUE}" "${PLMin}"   "${SCORE}"  "${NATAQUES}"  "${INFO_ATAQUES}"	>> "${OUT_INDEX}"
    printf \\n  										>> "${OUT_INDEX}"
	fi
}


# Analiza fichero.log de entrada y generada fichero.index
# Llamada: generarIndiceDeLog
# Salida: Ninguna
generarIndiceDeLog()
{
    # Datos de interes de cada URI recigida en el Log
    timestampUri=""
    uriLog=""
    PLminUri=""   # Menor PL a partir del cual se detecta esta URI como ataque
    scoreUri="0"
    numReglasUri="0"
    listaIDsReglasUri=""

    # Para buscar solo en la primera linea de la Seccion
    TIMESTAMP_EXTRAIDO=0	# Si 1, ya se ha leido (primera linea)
    URI_EXTRAIDA=0
    SIGUIENTE_TRANSACCION=0	# Saltar a la siguiente

    # Se lee el fichero de log  linea a linea
    #while read lineaLog ; do 
	while IFS= read -r lineaLog ; do

        # Identificar la seccion de la Transaccion en la que estamos
		INICIO_SECCION="0"
        SECCION_ACTUALtmp=$(detectarCambioSeccion  "${lineaLog}")
		if [ -n "${SECCION_ACTUALtmp}" ]; then 
			SECCION_ACTUAL=${SECCION_ACTUALtmp}
			INICIO_SECCION="1"
			if [ "${LAUNCH_MODE}" = "multiple" -a "${SECCION_ACTUALtmp}" = "${SECCIONA}" ]; then
				printf "\r                                          "
				printf "\r(%s/%s)"  "${uri_actual}"  "${NTOTAL_ENTRADAS}"
				uri_actual=$((uri_actual+1))	#Incrementamos contador de lectura
			fi
		fi
	
	case "${SECCION_ACTUAL}" in

	        "${SECCIONA}")		# A-COMIENZO TRANSACCION y TimeStamp
	    	    if [ "${TIMESTAMP_EXTRAIDO}" -eq 0 ]; then
	    		# Nueva Transaccion
	    		SIGUIENTE_TRANSACCION=0
    	        	# Buscamos TimeStamp
			TIMESTAMPtmp="$(extraerTimeStamp  "${lineaLog}")"
			if [ -n "${TIMESTAMPtmp}"  ]; then		# Si TIMESTAMPtmp no esta vacia
    			    timestampUri="${TIMESTAMPtmp}"
    			    TIMESTAMP_EXTRAIDO=1
			fi
		    fi
		;;

		"${SECCIONB}")		# B-URI
		    if [ "${URI_EXTRAIDA}" -eq 0 ]; then
			# Buscamos URI
			URItmp="$(extraerURI  "${lineaLog}")"
			if [ -n "${URItmp}"  ]; then		# Si URItmp no esta vacia
    			    uriLog="${URItmp}"
    			    URI_EXTRAIDA=1
			fi
		    fi
		;;

		"${SECCIONH}")		# C- PLmin, Score y sid's => Nº reglas
    		        # A) Buscamos Score Uri en lineaLog. Si se encuentra y es mayor al ultimo encontrado (en la actual seccion H) => Lo guardamos
					IDtmp="$(extraerId  "${lineaLog}")"
					ID_ANOMALA="0"

					while read line
						do
						if [ "${IDtmp}" = "${line}"  ]; then
							ID_ANOMALA="1"
							PLminUri="2"		
						fi					
					done < ${ID_RULES}

    				buscarCadena "${listaIDsReglasUri}"  "${IDtmp}"; [ $? -eq "1" ] && ENCONTRADA="1" || ENCONTRADA="0"   # Solo se añade ID si no esta ya (0)
    				if [ -n "${IDtmp}" -a  -n "${IDtmp##*[!0-9]*}" ]; then		# Si IDtmp no esta vacia y es un numero
    			    	if [ "${ENCONTRADA}" -eq "0"     -a    "${IDtmp}" -ne "${IDimpresion}" ]; then	# No vale arriba con "-a" (si IDtmp esta vacia => "-ne" da error)
    			    	    numReglasUri=$((numReglasUri+1))
    			    	    listaIDsReglasUri="${listaIDsReglasUri} ${IDtmp}"
    			    	fi
    				fi

 					PLmintmp="$(extraerPLmin  "${lineaLog}")"
				    if [ -n "${PLmintmp}" -a  -n "${PLmintmp##*[!0-9]*}" -a "${PLminUri}" != "1" ]; then		# Si PLmintmp no esta vacia y es un numero
    		    	    if [ -z "${PLminUri}" ]; then					# Si PL; actual vacio => Se guarda el leido
    		    		PLminUri="${PLmintmp}"
    		    	    elif [ "${PLmintmp}" -lt "${PLminUri}" ]; then			# Si PL actual no vacio => Solo se guarda si leido es menor
    		    		PLminUri="${PLmintmp}"
    		    	    fi
					elif [ ${INICIO_SECCION} -eq 0 -a -n "${lineaLog}" -a ${ID_ANOMALA} -eq 0 ]; then
#					elif [ "${INICIO_SECCION}" == "0" -a -n "${lineaLog}" ]; then
						PLminUri="1"		
					fi
    			
    		        # B) Buscamos Score Uri en lineaLog. Si se encuentra y es mayor al ultimo encontrado (en la actual seccion H) => Lo guardamos
    		        SCOREtmp="$(extraerScore  "${lineaLog}")"
    		        if [ -n "${SCOREtmp}" -a  -n "${SCOREtmp##*[!0-9]*}" ]; then		# Si SCOREtmp no esta vacia y es un numero
    			    [ "${SCOREtmp}" -gt "${scoreUri}" ] && scoreUri="${SCOREtmp}"	# No vale "-a" (si SCOREtmp esta vacia => "-gt" da error)
    			    #echo "valor dentro de sección B: "
    			    #echo "${scoreUri}"
    			fi
		;;

		"${SECCIONZ}")		# Z-FIN Transaccion
		
		    # Solo se hace la primera vez que se entra en la seccion
		    if [ "${SIGUIENTE_TRANSACCION}" -eq 0 ]; then
			# Imprimir en "fichero.index" la Transaccion (URI) analizada en "fichero.log"
			imprimirAtaqueIndice  "${timestampUri}"    "${uriLog}"     "${PLminUri}"     "${scoreUri}"    "${numReglasUri}"    "${listaIDsReglasUri}"
		    
			# Reseteo contadores
			TIMESTAMP_EXTRAIDO=0
			URI_EXTRAIDA=0
		    
			# Resetar valores
			timestampUri=""
			uriLog=""
			PLminUri=""   # Menos PL a partir del cual se detecta esta URI como ataque
			scoreUri="0"
			numReglasUri="0"
			listaIDsReglasUri=""
			
			# Saltar a la siguiente
			SIGUIENTE_TRANSACCION=1
		    fi
		;;
	esac		# \ "case" Analiza las distintas secciones de cada Transaccion
    done < "${IN}"		# \ "while" Analiza fichero de log de entrada linea a linea
}
#####





### Main()

# Impresion del comienzo del analisis
#NTOTAL_ENTRADAS="$(sed '/^$/d' "${IN}" | wc -l | cut -f1 -d " ")"		# No se cuentan las lineas vacias
NTOTAL_ENTRADAS=$(cat "${IN}" | grep -c ".*${SECCIONA}.*")
uri_actual=1

# 4) Generar "fichero.index" a partir del log obtenido
if [ ! -f "${MODLOG}" ]; then
	echo "No existe el fichero de entrada: ${MODLOG}. Se sale..."
	exit 1 
fi
generarIndiceDeLog
#####
