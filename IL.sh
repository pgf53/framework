#!/bin/sh

#### Cargar configuracion
. ./framework_config.sh
. ./framework_config_interna.sh


fichero_entrada="$1"

#################Multiple-basic####################
if [ ${URIS_FORMAT} = "basic" -a ${LAUNCH_MODE} = "multiple" ]; then

	#############IL-ModSecurity##################
	if [ "${IL_MODSECURITY}" -eq 1 ]; then
		nombre_fichero=$(basename ${fichero_entrada})
		nombre_fichero_index=$(printf "%s" "${nombre_fichero}" | sed "s/${FILE_IN_EXTENSION}/${INDEX_EXTENTION}/g")
		"${DIR_IL}ms-inspectorlog" -l "${fichero_entrada}" -t list -r "${MODSECURITY_RULES}" > "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"

	#############IL-Nemesida##################
	elif [ "${IL_NEMESIDA}" -eq 1 ]; then
		nombre_fichero=$(basename ${fichero_entrada})
		nombre_fichero_index=$(printf "%s" "${nombre_fichero}" | sed "s/${FILE_IN_EXTENSION}/${INDEX_EXTENTION}/g")
		"${DIR_IL}inspectorlog" -l "${fichero_entrada}" -t list -m "${NEMESIDA_RULES}" > "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"


	#############IL-Snort##################
	elif [ "${IL_SNORT}" -eq 1 ]; then
		nombre_fichero=$(basename ${fichero_entrada})
		nombre_fichero_index=$(printf "%s" "${nombre_fichero}" | sed "s/${FILE_IN_EXTENSION}/${INDEX_EXTENTION}/g")
		"${DIR_IL}inspectorlog" -l "${fichero_entrada}" -t list -r "${SNORT_RULES}" > "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"
	fi

#################Multiple-extended####################
#elif [ ${URIS_FORMAT} = "extended" -a ${LAUNCH_MODE} = "multiple" ]; then


#################1to1-basic####################
#elif [ ${URIS_FORMAT} = "basic" -a ${LAUNCH_MODE} = "1to1" ]; then

#################1to1-extended####################
#elif [ ${URIS_FORMAT} = "extended" -a ${LAUNCH_MODE} = "1to1" ]; then


fi
