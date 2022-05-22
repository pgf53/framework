/*
** INSPECTORLOG / MS-LOG
** Todos los derechos reservados
** All rights reserved
**
** Part of INSPECTORLOG tools
**
** Copyright (C) 2022, Jesús E. Díaz Verdejo
** Versión 3.5 JEDV - 20/01/2022
** 
** Changes (last):
**
* 
*	gcc -Wall -g -O0 msctest.c -o msctest -lmodsecurity
*	
*/
#include <sys/time.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"
#include "modsecurity/rules.h"
#include "modsecurity/rules_set.h"
#include "modsecurity/rule_message.h"
#include "modsecurity/intervention.h"
#include "inspector-common.h"
#include "ms-inspector.h"

#define DEBUG

/* Global variables */

ModSecurity *modsec = NULL;				// ModSec configuration/data
RulesSet *rules = NULL;					// ModSec rules
Transaction *trans = NULL;
ModSec_alert ms_alerts[MAX_MSALERTS];	// Alerts triggered by a log line
int nalerts = 0;						// Number of alerts triggered by a log line
unsigned char ms_conf_file[PATH_MAX+1];		// Modsecurity configuration file
unsigned char log_path[PATH_MAX+1];      	// Path to log file
unsigned char output_file[PATH_MAX+1]; 		// Path to output clean file
unsigned char outputms_file[PATH_MAX+1]; 		// Path to output detailed log ms file
bool mslogfile = false;

// Options (default)

bool outputf = false;
int log_type=LOG_APACHE;	// APACHE format by default 
bool nocase = false;
bool ealert = false;
bool warns = false;
bool resp_code = false;
bool uri_labels = false;

/* Problems with c99 
long begin, end;
long time_spent;
struct timespec tp;
*/

void free_ms() {
	
	// Clean up

//	if (rules) msc_rules_cleanup(rules);
//	if (modsec) msc_cleanup(modsec);

	return;
}

/****************/
/* Main program */
/****************/

int main(int argc, char ** argv) {
	int rc;
	int i;
	const char *error;						// Error handling modsec

	//For time measure
//    time_start();

    //Set function to be executed on exit
    if( atexit(free_ms) != 0){
        printf("[%s] Error in 'main program': Error at 'atexit' invocation\n",argv[0]);
    }
 
    printf("# ms-inspectorlog %s\n",INSPECTOR_VER);

#ifdef DEBUG2
    printf("> Processing start\n");
#endif
    
    //Parse command line arguments
    if( !parse_msArgs(argc, argv))
        exit(EXIT_FAILURE);

#ifdef DEBUG2
    printf("> Arguments read ...\n");


    // Rules loading 

	printf("Inicializando motor\n");
#endif

	/* MODSECURITY initialization */
	
    modsec = msc_init();
    msc_set_log_cb(modsec, msc_logdata);		// Logging function
	
	/* Loading rules/configuration */
	
    rules = msc_create_rules_set();
	rc = msc_rules_add_file(rules, ms_conf_file, &error);
    if (rc < 1) {
        printf("[ms-log] Error reading modsecurity conf/rules [%s]\n",error);
		exit(-1);
    }

#ifdef DEBUGRULES
	msc_rules_dump(rules);
#endif

	printf("#----- Analysis results ----------------------------\n");
    printf("# Alerts & signatures generated from: %s", argv[0]);
    for (int i=1; i < argc; i++) printf(" %s",argv[i]);
    printf("\n");
    
    // Read and process log file 
    
#ifdef DEBUTIME
    time(&rawtime); 
#endif

    ms_scan_logFile(log_path);

    // For time measure
//    time_end();
	
	// Clean up

	free_ms();

    return 0;
}