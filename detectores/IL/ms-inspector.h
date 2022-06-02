/*
** INSPECTORLOG / MS-LOG
** Todos los derechos reservados
** All rights reserved
**
** Part of INSPECTORLOG tools
**
** Copyright (C) 2022, Jesús E. Díaz Verdejo
** Version 3.5 JEDV - 24/02/2022
** Versión 1.0 JEDV - 20/01/2022
** 
** Changes (last):
**
** v3.5: Included as part of inspectorlog toolset
*/

#include <modsecurity/modsecurity.h>
#include <modsecurity/transaction.h>
#include <modsecurity/rules.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/rule_message.h>
#include <modsecurity/intervention.h>
#include "inspector-common.h"


// Global defines 

#define MSLOG
#define MAX_MSALERTS 20

/* Structures/data types */

typedef struct  {
	char file[PATH_MAX];
	int line;
	int id;
	char rev[WORDLENGTH];
	char msg[LINE_LENGTH];
	char data[LINE_LENGTH];
	int severity;
	char ver[WORDLENGTH];
	int maturity;
	float accuracy;
	char tag[URILENGTH];
	char hostname[WORDLENGTH];
	char uri[URILENGTH];
	char unique_id[WORDLENGTH];
	char ref[WORDLENGTH];
} ModSec_alert;

/* Global variables */

extern bool mslogfile;					// Output detailed modsecurity log to file
extern ModSecurity *modsec;				// ModSec configuration/data
extern RulesSet *rules;					// ModSec rules
extern ModSec_alert ms_alerts[MAX_MSALERTS];	// Alerts triggered by a log line
extern Transaction *trans;
extern int nalerts;						// Number of alerts triggered by a log line
extern unsigned char outputms_file[PATH_MAX+1]; 		// Path to output detailed modsecurity log file

/* Public functions */

void ms_scan_logFile(const char *fileName );
void msc_logdata(void *log, const void *data);
