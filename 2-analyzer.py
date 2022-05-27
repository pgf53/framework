#!/usr/bin/python3.6

import sys
import os
import linecache
import re

#Funciones
def find_all(a_str, sub):
	start = 0
	while True:
		start = a_str.find(sub, start)
		if start == -1:
			return
		yield start
		start += len(sub) # use start += 1 to find overlapping matches



file_log = sys.argv[1]	#fichero de log a procesar

#Creamos el nombre del fichero de index
file_index = file_log.replace(os.environ["LOG_EXTENSION"], os.environ["INDEX_EXTENTION"])
pos_index = file_index.rfind('/')
file_index = file_index[pos_index+1:]
path_index = os.environ["DIR_ROOT"] + "/" + os.environ["DIROUT_INDEX"] + "/" + file_index

### Lectura de Argumentos y Variables Globales
# Separadores de Seccion en cada Transaccion de "modsec_audit.log"
SECCIONA = "-A--"			# A: Contiene Comienzo y "TimeStamp"
SECCIONB = "-B--"			# B: Contiene URL
SECCIONH = "-H--"			# H: Contiene "Score" y "id"
SECCIONZ = "-Z--"			# Z: Final Transaccion
# Hay mas secciones, pero solo nos interesan estas

# Patrones para buscar datos de interes en "fichero.log" (formato "modsec_audit.log")
# TimeStamp Log
PATRONTimeStampinicio= '['
PATRONTimeStampfin= ']'

# PL minimo
PATRONPLinicio= '[tag "paranoia-level/'
PATRONPLfin= '"]'

# ID Regla
PATRONIDinicio= '[id "'
PATRONIDfin= '"]'

# URI
PATRONURIinicio = 'GET '
PATRONURIfin = 'HTTP'

# Score Reglas
#ModSecurityV2
PATRONSCOREinicio='[msg "Incoming Anomaly Score: '
PATRONSCOREfin='"]'
#ModSecurityV3
#PATRONSCOREinicio= '[msg "Inbound Anomaly Score Exceeded (Total Score: '
#PATRONSCOREfin= ')"]'

ids_registrados = []
score = 0
pl_min = 4


#Leemos fichero de log
if os.path.isfile(file_log) and os.stat(file_log).st_size != 0:
	with open(file_log) as f:
		for linea_log in f:
			if linea_log == "\n":
				continue
			if re.search(SECCIONA, linea_log):
				seccion = "SECCIONA"
			elif re.search(SECCIONB, linea_log):
				seccion = "SECCIONB"
			elif re.search(SECCIONH, linea_log):
				seccion = "SECCIONH"
			elif re.search(SECCIONZ, linea_log):
				seccion = "SECCIONZ"

			if seccion == "SECCIONA":
				inicio_timestamp=linea_log.find(PATRONTimeStampinicio)
				fin_timestamp=linea_log.find(PATRONTimeStampfin)
				if inicio_timestamp != -1:
					timestamp=linea_log[inicio_timestamp+1:fin_timestamp]
					ids_registrados = []
					score = 0
			if seccion == "SECCIONB":
				inicio_uri=linea_log.find(PATRONURIinicio)
				if inicio_uri != -1:
						fin_uri=linea_log.rfind(PATRONURIfin)
						uri=(linea_log[inicio_uri+len(PATRONURIinicio):fin_uri-1])
			if seccion == "SECCIONH":
				#inicio_id= list(find_all(linea_log, PATRONIDinicio))
				inicio_id = linea_log.find(PATRONIDinicio)
				fin_id = list(find_all(linea_log, PATRONIDfin))
				if inicio_id != -1 and fin_id != []:
					for id_superior in fin_id:
						if inicio_id < id_superior:
							if int(linea_log[inicio_id+len(PATRONIDinicio):id_superior]) != 1000:
								ids_registrados.append(linea_log[inicio_id+len(PATRONIDinicio):id_superior])
							break
				inicio_score = linea_log.find(PATRONSCOREinicio)
				fin_score = list(find_all(linea_log, PATRONSCOREfin))
				if inicio_score != -1 and fin_score != []:
					for score_superior in fin_score:
						if inicio_score < score_superior:
							score_linea = linea_log[inicio_score+len(PATRONSCOREinicio):score_superior]
							if int(score_linea) > int(score):
								score = score_linea
							break
				inicio_pl = linea_log.find(PATRONPLinicio)
				if inicio_pl != -1:
					pl_linea = linea_log[inicio_pl+len(PATRONPLinicio)]
					if int(pl_linea) < int(pl_min):
						pl_min = pl_linea
			if seccion == "SECCIONZ":
				ids_registrados = list(dict.fromkeys(ids_registrados))
				identificadores = ""
				for identificador in ids_registrados:
					if identificadores != "":
						identificadores = identificadores + "\t" + "[" + identificador + "]"
					else:
						identificadores = "[" + identificador + "]"
				linea_index = "TimeStamp [" + timestamp + "]" + "\t" + "Uri [" + uri + "]" + "\t" + "PLmin [" + str(pl_min) + "]" + "\t" + "Score [" + str(score) + "]" + "\t" + "Nattacks [" + str(len(ids_registrados)) + "]" + "\t" + identificadores
				f = open(path_index, "a")
				f.write("%s" %linea_index)
				f.write("\n")
				f.close()
else:
	open(path_index, 'a').close()
