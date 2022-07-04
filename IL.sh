#!/bin/sh

#### Cargar configuracion
. ./framework_config_interna.conf

fichero_entrada="$1"
nombre_fichero=$(basename ${fichero_entrada})
nombre_fichero_index=$(printf "%s" "${nombre_fichero}" | sed "s/${FILE_IN_EXTENSION}/${INDEX_EXTENTION}/g")

#################Multiple-basic####################
if [ ${URIS_FORMAT} = "basic" -a ${LAUNCH_MODE} = "multiple" ]; then

	#############IL-ModSecurity##################
	[ "${IL_MODSECURITY}" -eq 1 ] && "${DIR_IL}ms-inspectorlog" -l "${fichero_entrada}" -t list -r "${MODSECURITY_RULES}" > "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"

	#############IL-Nemesida##################
	[ "${IL_NEMESIDA}" -eq 1 ] && "${DIR_IL}inspectorlog" -l "${fichero_entrada}" -t list -m "${NEMESIDA_RULES}" > "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"

	#############IL-Snort##################
	[ "${IL_SNORT}" -eq 1 ] && "${DIR_IL}inspectorlog" -l "${fichero_entrada}" -t list -r "${SNORT_RULES}" > "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"

#################Multiple-extended####################
elif [ ${URIS_FORMAT} = "extended" -a ${LAUNCH_MODE} = "multiple" ]; then
	awk '{print $2}' "${fichero_entrada}" > "${DIR_TMP}/${nombre_fichero}"

	#############IL-ModSecurity##################
	[ "${IL_MODSECURITY}" -eq 1 ] && "${DIR_IL}ms-inspectorlog" -l "${DIR_TMP}/${nombre_fichero}" -t list -r "${MODSECURITY_RULES}" > "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"

	#############IL-Nemesida##################
	[ "${IL_NEMESIDA}" -eq 1 ] && "${DIR_IL}inspectorlog" -l "${DIR_TMP}/${nombre_fichero}" -t list -m "${NEMESIDA_RULES}" > "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"

	#############IL-Snort##################
	[ "${IL_SNORT}" -eq 1 ] && "${DIR_IL}inspectorlog" -l "${DIR_TMP}/${nombre_fichero}" -t list -r "${SNORT_RULES}" > "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"

	 rm -f "${DIR_TMP}/${nombre_fichero}"




#################1to1-basic####################
elif [ ${URIS_FORMAT} = "basic" -a ${LAUNCH_MODE} = "1to1" ]; then

	nombre_fichero_index="$2"

	#############IL-ModSecurity##################
	if [ "${IL_MODSECURITY}" -eq 1 ]; then
		"${DIR_IL}ms-inspectorlog" -l "${fichero_entrada}" -t list -r "${MODSECURITY_RULES}" > "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}"
		lineas_index=$(wc -l "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}" | cut -d' ' -f'1')
		if [ "${lineas_index}" -eq 5 ]; then
			sed -e '5d;1,3d' "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}" >> "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"
		else
			touch "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"
		fi
		rm -f "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}"
	fi

	#############IL-Nemesida##################
	if [ "${IL_NEMESIDA}" -eq 1 ]; then 
		"${DIR_IL}inspectorlog" -l "${fichero_entrada}" -t list -m "${NEMESIDA_RULES}" > "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}"
		lineas_index=$(wc -l "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}" | cut -d' ' -f'1')
		if [ "${lineas_index}" -eq 11 ]; then
			sed -e '10,11d;1,8d' "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}" >> "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"
		else
			touch "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"
		fi
		rm -f "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}"
	fi

	#############IL-Snort##################
	if [ "${IL_SNORT}" -eq 1 ]; then
		"${DIR_IL}inspectorlog" -l "${fichero_entrada}" -t list -r "${SNORT_RULES}" > "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}"
		lineas_index=$(wc -l "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}" | cut -d' ' -f'1')
		if [ "${lineas_index}" -eq 15 ]; then
			sed -e '14,15d;1,12d' "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}" >> "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"
		else
			touch "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"
		fi
		rm -f "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}"
	fi

#################1to1-extended####################
elif [ ${URIS_FORMAT} = "extended" -a ${LAUNCH_MODE} = "1to1" ]; then

	nombre_fichero_index="$2"
	awk '{print $2}' "${fichero_entrada}" > "${fichero_entrada}-sin-id"

	#############IL-ModSecurity##################
	if [ "${IL_MODSECURITY}" -eq 1 ]; then
		"${DIR_IL}ms-inspectorlog" -l "${fichero_entrada}-sin-id" -t list -r "${MODSECURITY_RULES}" > "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}"
		lineas_index=$(wc -l "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}" | cut -d' ' -f'1')
		if [ "${lineas_index}" -eq 5 ]; then
			sed -e '5d;1,3d' "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}" >> "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"
		else
			touch "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"
		fi
	fi

	#############IL-Nemesida##################
	if [ "${IL_NEMESIDA}" -eq 1 ]; then 
		"${DIR_IL}inspectorlog" -l "${fichero_entrada}-sin-id" -t list -m "${NEMESIDA_RULES}" > "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}"
		lineas_index=$(wc -l "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}" | cut -d' ' -f'1')
		if [ "${lineas_index}" -eq 11 ]; then
			sed -e '10,11d;1,8d' "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}" >> "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"
		else
			touch "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"
		fi
	fi

	#############IL-Snort##################
	if [ "${IL_SNORT}" -eq 1 ]; then
		"${DIR_IL}inspectorlog" -l "${fichero_entrada}-sin-id" -t list -r "${SNORT_RULES}" > "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}"
		lineas_index=$(wc -l "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}" | cut -d' ' -f'1')
		if [ "${lineas_index}" -eq 15 ]; then
			sed -e '14,15d;1,12d' "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}" >> "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"
		else
			touch "${DIR_ROOT}/${DIROUT_INDEX}/${nombre_fichero_index}"
		fi
	fi

		rm -f "${DIR_TMP_FAST}/1to1-IL_${NOMBRE_RAIZ}${FILE_IN_EXTENSION}" "${fichero_entrada}-sin-id"

fi
