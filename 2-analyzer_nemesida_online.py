#!/usr/bin/python3.6

import sys
import os
import linecache
import re

file_log = sys.argv[1]	#fichero de log a procesar
num_uris_log_totales = sys.argv[2] #Número de líneas del log a procesar
file_access = os.environ["PATH_ACCESS_LOG"]

#Creamos el nombre del fichero de index
file_index = file_log.replace(os.environ["LOG_EXTENSION"], os.environ["INDEX_EXTENTION"])
pos_index = file_index.rfind('/')
file_index = file_index[pos_index+1:]
path_index = os.environ["DIR_ROOT"] + "/" + os.environ["DIROUT_INDEX"] + "/" + file_index

ids_registrados = []
num_linea_log_actual = 1
NEMESIDA_WAF = "Nemesida WAF: the request "
peticion = ""
inicio = 1

#Leemos fichero de log
if os.path.isfile(file_log) and os.stat(file_log).st_size != 0:
	with open(file_log) as f:
		for linea_log in f:
			if os.environ["LAUNCH_MODE"] == "multiple":
				print(str(num_linea_log_actual) + "/" + num_uris_log_totales)
				num_linea_log_actual += 1
			if re.search(NEMESIDA_WAF, linea_log):
				x = linea_log.split()
				if x[9] != peticion:
					if inicio == 1:
						inicio = 0
					else:
						ids_registrados = list(dict.fromkeys(ids_registrados))
						identificadores = ""
						for identificador in ids_registrados:
							if identificadores != "":
								identificadores = identificadores + "\t" + "[" + identificador + "]"
							else:
								identificadores = "[" + identificador + "]"
						linea_index = "TimeStamp [" + timestamp + "]" + "\t" + "Uri [" + uri + "]" + "\t" + "Nattacks [" + str(len(ids_registrados)) + "]" + "\t" + identificadores
						ids_registrados = []
						f = open(path_index, "a")
						f.write("%s" %linea_index)
						f.write("\n")
						f.close()

					peticion = x[9]
					timestamp = x[0] + " " + x[1]

					#Extraemos la uri del access.log (error.log corta uris largas)
					with open(file_access) as f2:
						for linea_access in f2:
							if re.search(peticion, linea_access):
								y = linea_access.split()
								uri = y[5]
								break
							
					if x[10] == "blocked":
						ids_registrados.append(x[14])
					elif x[10] == "contains":
						ids_registrados.append(x[13])
				else:
						if x[10] == "blocked":
							ids_registrados.append(x[14])
						elif x[10] == "contains":
							ids_registrados.append(x[13])

		ids_registrados = list(dict.fromkeys(ids_registrados))
		identificadores = ""
		for identificador in ids_registrados:
			if identificadores != "":
				identificadores = identificadores + "\t" + "[" + identificador + "]"
			else:
				identificadores = "[" + identificador + "]"
		linea_index = "TimeStamp [" + timestamp + "]" + "\t" + "Uri [" + uri + "]" + "\t" + "Nattacks [" + str(len(ids_registrados)) + "]" + "\t" + identificadores
		f = open(path_index, "a")
		f.write("%s" %linea_index)
		f.write("\n")
		f.close()
