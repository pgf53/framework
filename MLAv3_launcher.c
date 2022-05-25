/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 - 2021 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"


//para que las rutas funcionen, debe evitarse que terminen en '/'
char main_rule_uri[] = "detectores/ModSecurity/offline/basic_rules.conf"; // fichero de configuración de ModSecurity V3

void cb(void *log, const void *data)
{
    // swallow it
    return;
}

int main (int argc, char **argv)
{

	if(argc!=2)
	{
		printf("Formato:\n");
		printf("./launcher.out line \n");
		printf("Dataset: fichero con las uris a analizar.\n");
		exit(1);
	}
	

	//const char* uri = argv[1];
	const char* file_uri = argv[1];
	FILE *in_file = fopen(file_uri, "r");
		if (!in_file) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }


	int ret;
    const char *error = NULL;
    ModSecurity *modsec;
    Transaction *transaction = NULL;
    RulesSet *rules;

	struct stat sb;
	if (stat(file_uri, &sb) == -1) {
        perror("stat");
        exit(EXIT_FAILURE);
    }

    char *file_contents = malloc(sb.st_size);

	// Comenzamos el proceso de creación y envío de la transacción. 
	// Puesto que no vamos a cambiar las reglas en tiempo de ejecución,
	// lo óptimo es establecer los parámetros de conexión y reglas solo
	// una vez. De esta forma el proceso es más eficiente. 
	modsec = msc_init();

    msc_set_connector_info(modsec, "ModSecurity-test v0.0.1-alpha (Simple " \
        "example on how to use ModSecurity API");

    rules = msc_create_rules_set();

    ret = msc_rules_add_file(rules, main_rule_uri, &error);
    if (ret < 0) {
        fprintf(stderr, "Problems loading the rules --\n");
        fprintf(stderr, "%s\n", error);
        goto end;
    }

    msc_rules_dump(rules);
	msc_set_log_cb(modsec, cb);

	while (fscanf(in_file, "%[^\n] ", file_contents) != EOF) {
		transaction = msc_new_transaction(modsec, rules, NULL);

// phase 0
    msc_process_connection(transaction, "127.0.0.1", 12345, "127.0.0.1", 80);
// es necesario establecer la cabecera
	//msc_add_request_header(transaction, (unsigned char *)"Host", (unsigned char *)"localhost");
	//msc_add_request_header(transaction, (unsigned char *)"User-Agent", (unsigned char *)"msc_process_uri");
	//msc_add_request_header(transaction, (unsigned char *)"Accept", (unsigned char *)"*/*");
	msc_add_request_header(transaction, (unsigned char *)"Host", (unsigned char *)"localhost");
	msc_add_request_header(transaction, (unsigned char *)"User-Agent", (unsigned char *)"Apache/2.2.15 (Red Hat) (internal dummy connection)");
	msc_add_request_header(transaction, (unsigned char *)"Accept", (unsigned char *)"Yes");
	msc_append_request_body(transaction, (unsigned char *)"", 0);
//    msc_process_uri(transaction, uri,"GET", "1.1");
	msc_process_uri(transaction, file_contents, "GET", "1.1");
// phase 1 
    msc_process_request_headers(transaction);
// phase 2
    msc_process_request_body(transaction);
/*
// phase 3
    msc_process_response_headers(transaction, 200, "HTTP 1.3");
// phase 4
    msc_process_response_body(transaction);
*/

// phase 5
    msc_process_logging(transaction);

  																	}
end:
	msc_rules_cleanup(rules);
	msc_cleanup(modsec);

	free(file_contents);
    fclose(in_file);
    exit(EXIT_SUCCESS);


    return 0;
}



