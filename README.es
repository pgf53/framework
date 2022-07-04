# framework

Herramienta que permite la inserción de módulos de seguridad de manera rápida y flexible que tienen por objeto el análisis de uris.


Para realizar un análisis completo, introducir fichero de uris en directorio '01-Uri/', establecer configuración deseada y ejecutar script '0-Framework.sh'.

Scripts:

./install.sh

Ejecutar para instalar dependencias de framework y de sus detectores integrados.

./0-Frameworks

Ejecuta análisis completo atendiendo a la configuración establecida. Orden de invocación de los scripts: 1-Launcher.sh ---> 2-analyzer*.py ---> 3-classify*.py

./1-Launcher.sh fichero_uri

 Realiza el lanzamiento según la configuración establecida. Genera fichero de log.
 
 fichero_uri: fichero uri de entrada

./2-analyzer.py fichero_log num_uris

Realiza el análisis del log generado en el punto anterior para los IDS's modSecurityV2 y modSecurityV3. Genera fichero de index.

fichero_log: fichero log de entrada
num_uris: número de uris presentes en el log (se usa meramente para mostrar progeso del análisis)

./2-analyzer_nemesida_online.py fichero_log num_uris

Igual que en caso anterior pero para detector nemesida online

./3-classify.py fichero_uri uris_totales fichero_index

Realiza la clasificación de las uris (en 'limpias' o 'ataques') comparando las uris del fichero de entrada con las detectadas como ataques en el fichero de index. 

fichero_uri: fichero uri de entrada
uris_totales: número de uris de fichero de entrada. Se usa para mostrar progreso de la clasificación
fichero_index: fichero de index usado en la clasificación de las uris

./3-classify_IL.py 

Similar al anterior pero usado en la clasificación de los detectores integrados en IL. 

./IL.sh fichero_uri

Ejecuta detector de IL establecido en la configuración.

fichero_uri: fichero uri de entrada a analizar

MLAv3_launcher.out fichero_uri

Ejecuta detector de ModSecurityV3.

fichero_uri: fichero uri de entrada a analizar

./zlimpiar.sh

Limpia directorios para realizar un nuevo análisis.






