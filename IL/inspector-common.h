#ifndef __INSPECTOR_COMMON
#define __INSPECTOR_COMMON

/*
** INSPECTORLOG
** Todos los derechos reservados
** All rights reserved
**
** Copyright (C) 2017, Jesús E. Díaz Verdejo
** Versión 3.5 JEVD - 20/01/2022
** Versión 3.4 JEDV - 25/11/2021
** Versión 3.0 JEDV - 19/12/2017
** 
** Changes:
**	v3.5: Added ms-log tool - Files reorganized
**		  Increased NEMESIDA_OFFSET to 300M to support er rules below
**		  Added PUT method
*/

#define _XOPEN_SOURCE 700

#undef DEBUG
#undef DEBUG2

#define INSPECTOR_VER "v3.5"

//C INCLUDES
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>
#include <limits.h>
#include <ftw.h>
#include <pcre.h>

// Defines

#define MAX_URI_RULES 50000     // Maximun number of rules to store (STATIC ALLOCATION) 
#define PATH_MAX 16385          // Maximum path size 
#define URILENGTH 16385         // Maximum length of a URI?? -> http://stackoverflow.com/questions/2659952/maximum-length-of-http-get-request
#define WORDLENGTH 128
#define LINE_LENGTH	1024			
#define MAXLOG_LINE 16385		// Maximum length of a log line
#define MAX_ALERTS_PER_URI 124	// Maximum numbero of alerts triggered by a single URI
#define MYSQL_QUERYLENTGH 16385	// Maximum length of a query
#define SNORT_RULE_MAX 20096    // Maximum length of a Snort rule 
#define RULES_DIR "rules"       // Default rules directory (Snort)

#define MAX_REFERENCES 6		// Maximum number of references per rule
#define MAX_PATTERNS 12			// Maximum number of content or alike fields (patterns to search for) per rule
#define MAX_PCRE 4				// Maximum number of regular expressiones per rule
#define CONTENT_LENGTH 1024		// Maximum length of a pattern
#define MAX_BYTECODES 100		// Maximum lenght of a string of bytecodes

#define RESP_CODE_INVALID 400		// Response code from which records are dissmissed (if filtering by response code)

// Various detectors / rules

#define NSIDS 2					// Number of different sources (engines)
#define SNORT 1
#define NEMESIDA 2

// SIDS are stored adding an offset per source

#define SNORTSID_OFFSET 0			
#define SURICATA_OFFSET 2000000
#define NEMESIDA_OFFSET 300000000

#define SCORE_THD 8				// Threshold for nemesida scores - Alert only if score is bigger

// Rule parsing / fields 

// Number of fields
#define NEMESIDA_HEADER_TOKENS 6
#define SNORT_HEADER_TOKENS 7

// Field positions (snort)
#define ACTION 1                // Acción de la regla: "alert"
#define PROTO 2                 // Protocolo: "tcp"
#define IPORIG 3                // Direccion IP origen: $EXTERNAL_NET (toda la red)
#define PORIG 4                 // Puerto IP origen: any (cualquiera)
#define IPSDEST 5               // Direccion IP destino: $HOME_NET (toda nuestra red)
#define PDEST 6                 // Puerto IP destino: any (cualquiera)
#define DIR 7                   // Dirección de la operación: "->" (puede ser ->, <-, )

// Field positions (nemesida)
#define NEM_SID 1				// SID for nemesida rule
#define NEM_TYPE 2				// Type of nemesida rule 
#define NEM_CONTENT 3				// Content of the rule
#define NEM_ATTACK_TYPE	4			// Type of attack_type
#define NEM_SCORE 5					// Score of the attack
#define NEM_FIELD 6					// Fields to apply rule

// Log file formats

#define LOG_APACHE 0		// Apache standard format
#define LOG_WELLNESS 1		// Apache modified (Wellness format)
#define LOG_LIST 2			// Raw uri list (optionally with response codes 
#define LOG_URI 3			// URI format: length uri (optional response code)
#define LOG_ELIST 4			// Extended list: method uri response_code response_size

// Comparison operation codes 

#define URILENEQ 3
#define URILENGT 2
#define URILENLT 1

/* Structures  (common) */

typedef enum{
    GET,
    POST,
    HEAD,
    PROPFIND,
	PUT,
	NONE
}_requestMethod;

typedef enum{
    _1_0,
    _1_1,
    _VOID
}_httpProtocol;

/*  Log entries in a format known as the Common Log Format (CLF).
    http://en.wikipedia.org/wiki/Common_Log_Format
*/

#define APACHE_LOG_ITEMS 11 			//Number of elements on Apache Logs

typedef struct {

    unsigned char ip_address[16];       //IP address of the client
    char user_identifier[WORDLENGTH];   //RFC 1413 identify
    char user_id[WORDLENGTH];           //Userid of the person requesting the document
    struct tm time;                     //Time in strftime format -> tm struct
    _requestMethod request_method;
    char URI[URILENGTH];                //Maximum length of a URI?? -> http://stackoverflow.com/questions/2659952/maximum-length-of-http-get-request
	unsigned int urilen;				// Length of the URI
    _httpProtocol Protocol;             //HTTP Protocol
    int16_t status_code;                //HTTP Status Code -> http://www.w3.org/Protocols/rfc2616/rfc2616.txt
    int32_t return_size;                //The size of the object returned to the client

    /* --- Additional fields for Combined Log Format ---*/
    char referer[URILENGTH];
    char user_agent[URILENGTH];         // UserAgent maximum length -> http://httpd.apache.org/docs/2.4/mod/core.html#limitrequestfieldsize

	char label[WORDLENGTH];				// Label (optional) of the log record
} Apache_logEntry;

// Mapping (indexes) of fields in a log line from space-based splitting

typedef struct log_map {
        int ip;
        int useridentifier;
        int userid;
        int timestamp;
        int dif;
        int method;
        int uri;
        int protocol;
        int status_code;
        int return_size;
        int referer;
        int user_agent;
		int label;
		int nfields;		// Number of "active" fields
} log_map;

// GLOBAL VARIABLES

// Options

extern bool outputf;                        // Output clean URIs to file 
extern int log_type;                        // Log file format code (0 = apache standard, 1 = list, 2 = wellness, 3 = URI)
extern bool nocase;                         // Activate global nocase (overrides per rule nocase)
extern bool ealert;                         // Output alerts in extended format (msg/description + sid)
extern bool warns;                          // Generates warnings for not found %encodings
extern bool resp_code;						// Activate filtering by response code
extern bool uri_labels;						// Use of labels for log entries
extern int nlineas;							// Number of lines parsed from a log file

// Files/Input/Output

extern unsigned char log_path[PATH_MAX+1];      	// Path to log file
extern unsigned char output_file[PATH_MAX+1]; 		// Path to output clean file

#ifdef DEBUGTIME

extern time_t rawtime;
extern struct tm *timeinfo;

#endif

/* Public functions prototypes  */

/* logs-common.c */

void init_log_map(log_map *m );
int parse_apache_logEntry(char * logLine, Apache_logEntry * logEntry, log_map map, int logLinelen);
int parse_list_logEntry(char * logLine, Apache_logEntry * logEntry, log_map map, int logLinelen);
int parse_elist_logEntry(char * logLine, Apache_logEntry * logEntry, log_map map, int logLinelen);
int parse_uri_logEntry(char * logLine, Apache_logEntry * logEntry, log_map map, int logLinelen);
void init_Apache_logEntry(Apache_logEntry * logEntry);
int compare( const void* a, const void* b);


#endif
