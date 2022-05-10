#!/usr/bin/python3.6

import sys
import os
import linecache

#funciones

#Extrae la uri de una línea index.
#Entradas: línea de fichero de index.
#Devuelve: campo uri de la línea pasada como argumento.
def extrae_uri(line_index):

	start_character = os.environ["URI_START"]
	start_character = "	" + start_character
	end_character = os.environ["URI_END"]
	end_character = end_character + "	"
	pos_start = line_index.find(start_character)
	if pos_start != -1:
		line_index_end = line_index[pos_start:]
		pos_end = line_index_end.find(end_character) + pos_start
	else:
		pos_end = line_index.find(end_character)

	#1º Posibilidad: uri en el medio
	if pos_start != -1 and pos_end != pos_start - 1:
		uri_index = line_index[pos_start+len(start_character):pos_end]

	#2º Posibilidad: uri al final
	elif pos_start != -1 and pos_end == pos_start - 1:
		pos_end = line_index.find('\n')
		if pos_end != -1:
			uri_index = line_index[pos_start+len(start_character):pos_end-1]
		else:
			uri_index = line_index[pos_start+len(start_character):-1]

	#3º Posibilidad: uri al principio
	elif pos_start == -1 and pos_end != -1:
		uri_index = line_index[len(os.environ["URI_START"]):pos_end]

	else:
		sys.exit("Error: no se ha encontrado ninguna uri en el fichero de 'index'")

	return uri_index

#Elimina el campo seleccionado de la línea de index.
#Entradas: línea de fichero de index, patrón de inicio del campo a eliminar, patrón de fin del campo a eliminar.
#Devuelve: línea de index sin el campo seleccionado.
def elimina_patron(line_index, patron_inicio, patron_fin):

	start_character = patron_inicio
	start_character = "	" + start_character
	end_character = patron_fin
	end_character = end_character + "	"
	pos_start = line_index.find(start_character)
	if pos_start != -1:
		line_index_end = line_index[pos_start:]
		pos_end = line_index_end.find(end_character) + pos_start
	else:
		pos_end = line_index.find(end_character)

	#1º Posibilidad: patron en el medio
	if pos_start != -1 and pos_end != pos_start - 1:
		new_line_index = line_index[:pos_start] + line_index[pos_end+len(end_character)-1:]

	#2º Posibilidad: patron al final
	elif pos_start != -1 and pos_end == pos_start - 1:
		new_line_index = line_index[:pos_start]


	#3º Posibilidad: patron al principio
	elif pos_start == -1 and pos_end != -1:
		new_line_index = line_index[pos_end+len(end_character):]

	else:
		print("No se ha encontrado ningún patrón coincidente, nada que eliminar")

	return new_line_index

#Escribe la uri detectada como ataque en los ficheros de ataque
#Entradas: línea de fichero de index, uri de fichero de entrada, posición que ocupa la uri en el fichero de entrada.
def inserta_attack(line_index, uri, num_uri):

	new_line_index = elimina_patron(line_index, os.environ["TIME_START"], os.environ["TIME_END"])
	new_line_index = elimina_patron(new_line_index, os.environ["URI_START"], os.environ["URI_END"])
	if os.environ["URIS_FORMAT"] == "basic":
		inicio = os.environ["PACKET"] + " [" + str(num_uri) + "]" + "	" + uri
		attack_line = inicio
	elif os.environ["URIS_FORMAT"] == "extended":
		pos_identificador = uri.find("	")
		identificador = uri[:pos_identificador]
		inicio = os.environ["ID"] + " [" + identificador + "]" + "	" + uri[pos_identificador+1:]
		attack_line = inicio

	attack_info_line = inicio + "	" + new_line_index
	#Escribimos en fichero de '-info.attacks'
	with open(OUT_ATTACKS_INFO, 'a') as f:
		f.write(attack_info_line)
		f.write("\n")
	#Escribimos en fichero de '.attacks'
	with open(OUT_ATTACKS, 'a') as f:
		f.write(attack_line)
		f.write("\n")

#Escribe la uri detectada como limpia en el fichero clean
#Entradas: uri de fichero de entrada, posición que ocupa la uri en el fichero de entrada.
def inserta_clean(uri, num_uri):
	if os.environ["URIS_FORMAT"] == "basic":
		inicio = os.environ["PACKET"] + " [" + str(num_uri) + "]"
		clean_line = inicio + "	" + uri
	elif os.environ["URIS_FORMAT"] == "extended":
		pos_identificador = uri.find("	")
		identificador = uri[:pos_identificador]
		inicio = os.environ["ID"] + " [" + identificador + "]"
		clean_line = inicio + "	" + uri[pos_identificador+1:]

	#Escribimos en fichero de 'clean'
	with open(OUT_CLEAN, 'a') as f:
		f.write(clean_line)
		f.write("\n")


#Para su uso es necesario exportar previamente las variables de config.sh

##### Main ########

#Entradas comunes a los dos modos de lanzamiento
file_uri= sys.argv[1]	#fichero de uri de entrada
uris_totales = sys.argv[2]	#numero de uris totales del fichero de entrada

#Creamos el nombre del fichero de ataque
file_attacks = file_uri.replace(os.environ["FILE_IN_EXTENSION"], os.environ["ATTACKS_EXTENSION"])
pos_attack = file_attacks.rfind('/')
file_attacks = file_attacks[pos_attack+1:]

#Creamos el nombre del fichero de ataque con información extendida
file_info_attacks = file_uri.replace(os.environ["FILE_IN_EXTENSION"], os.environ["INFO_ATTACKS_EXTENSION"])
pos_info_attack = file_info_attacks.rfind('/')
file_info_attacks = file_info_attacks[pos_info_attack+1:]

#Extraer nomre y extension del ataque con información extendida
#file_info_hide_attacks = file_uri.replace(os.environ["FILE_IN_EXTENSION"], os.environ["INFO_ATTACKS_HIDE_EXTENSION"])
#pos_info_hide_attack = file_info_hide_attacks.rfind('/')
#file_info_hide_attacks = file_info_hide_attacks[pos_info_hide_attack+1:]

##Creamos el nombre del fichero de limpias
file_clean = file_uri.replace(os.environ["FILE_IN_EXTENSION"], os.environ["CLEAN_EXTENSION"])
pos_clean = file_clean.rfind('/')
file_clean = file_clean[pos_clean+1:]

#Salidas
OUT_ATTACKS = os.environ["DIR_ROOT"] + "/" + os.environ["DIROUT_ATTACKS"] + "/" + file_attacks	#fichero de ataque generado
OUT_ATTACKS_INFO = os.environ["DIR_ROOT"] + "/" + os.environ["DIROUT_ATTACKS"] + "/" + file_info_attacks	#fichero resumen de ataques
OUT_CLEAN = os.environ["DIR_ROOT"] + "/" + os.environ["DIROUT_CLEAN"] + "/" + file_clean	#fichero de limpias generado


line_number_index = 1
num_uri = 1
if os.environ["LAUNCH_MODE"] == "multiple":

	#Entrada del modo múltiple
	file_index = sys.argv[3]	#fichero de index de entrada

	with open(file_uri) as f:
		for uri in f:
			#Imprimimos progreso
			print(str(num_uri) + "/" + uris_totales)
			#Exraemos uri de la línea del index
			line_index = linecache.getline(file_index, line_number_index)
			#Elimimamos caracter nueva linea de la uri a analizar si lo hubiese
			if uri[len(uri)-1] == "\n":
				pos_new_line = uri.rfind("\n")
				uri = uri[:pos_new_line]
			#Comprobamos que el ficero .index no ha terminado
			if line_index != "":
				uri_index = extrae_uri(line_index)

				#Elimimamos caracter nueva linea de la línea del index si lo hubiese 
				if line_index[len(line_index)-1] == "\n":
					pos_new_line = line_index.rfind("\n")
					line_index = line_index[:pos_new_line]

				#Comprobamos el formato de entrada
				if os.environ["URIS_FORMAT"] == "basic":
					uri_in = uri
				elif os.environ["URIS_FORMAT"] == "extended":
					pos_identificador = uri.find("	")
					uri_in = uri[pos_identificador+1:]
					
				if os.environ["LAUNCH_TYPE"] == "online-local" or os.environ["LAUNCH_TYPE"] == "online-remoto":

					#Codificiamos la uri de entrada ('#' y ' ')
					uri_encoded = uri_in.replace(" ", "%20")
					uri_encoded = uri_encoded.replace("#", "%23")
					
					if uri_encoded == uri_index:
						inserta_attack(line_index, uri, num_uri)
						line_number_index += 1
					else:
						inserta_clean(uri, num_uri)

				elif os.environ["LAUNCH_TYPE"] == "offline":
					if uri_in == uri_index:
						inserta_attack(line_index, uri, num_uri)
						line_number_index += 1
					else:
						inserta_clean(uri, num_uri)
			else:
				inserta_clean(uri, num_uri)

			num_uri += 1
elif os.environ["LAUNCH_MODE"] == "1to1":

	#Entradas del modo 1to1
	line_index = sys.argv[3]
	uri = sys.argv[4]
	num_uri = sys.argv[5]

	if line_index != "uri_limpia":
		uri_index = extrae_uri(line_index)
	else:
		uri_index = "limpia"

	#Comprobamos el formato de entrada
	if os.environ["URIS_FORMAT"] == "basic":
		uri_in = uri
	elif os.environ["URIS_FORMAT"] == "extended":
		pos_identificador = uri.find("	")
		uri_in = uri[pos_identificador+1:]

	if os.environ["LAUNCH_TYPE"] == "online-local" or os.environ["LAUNCH_TYPE"] == "online-remoto":
		
		#Codificiamos la uri de entrada ('#' y ' ')
		uri_encoded = uri_in.replace(" ", "%20")
		uri_encoded = uri_encoded.replace("#", "%23")
				
		if uri_encoded == uri_index:
			inserta_attack(line_index, uri, num_uri)
		else:
			inserta_clean(uri, num_uri)

	elif os.environ["LAUNCH_TYPE"] == "offline":
		if uri_in == uri_index:
			inserta_attack(line_index, uri, num_uri)
		else:
			inserta_clean(uri, num_uri)

