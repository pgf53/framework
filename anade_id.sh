#!/bin/sh

#Recibe como entrada un fichero .uri y le añade un idetificador del tipo: ID	URI

identificador=10
uris_totales=$(wc -l "$1" | cut -d' ' -f1)

while IFS= read -r input
do
printf "%s	%s\n" "${identificador}" "${input}" >> 01-Uri/$1
identificador=$((identificador+10))
done < "$1"
