/*
** INSPECTORLOG
** Todos los derechos reservados
** All rights reserved
**
** Copyright (C) 2017, Jesús E. Díaz Verdejo
** Version 3.5 JEDV - 24/02/2022
** Versión 3.4 JEDV - 25/11/2021
** Versión 3.0 JEDV - 19/12/2017
** 
** Changes (last):
**
**   v3.5: No changes in this program 
**   v3.4: Nemesida rules support (differentiated path and query management) - For nemesida only: %20 decoded before comparisons
**   v3.4: Optional filtering of URIs by response code >=400
**   v3.4: Differentiated management of list, elist and URI log types, including optional response code
**   v3.4: Optional labels for log entries
**   v3.4: Authomatic discard of not recognized methods (only Apache like logs)
**   v3.4: Considering NULL CHAR as potential part of a URI by explicitly using URI length - TODO: Not really used during comparison (engine)
**   v3.4: Added extended list format
*/

//some extra functions that are defined in the X/Open and POSIX standards.
#define _XOPEN_SOURCE 700

#define _GNU_SOURCE

//C INCLUDES
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include <ftw.h>


//INSPECTORLOG INCLUDES
#include <inspector-common.h>
#include <inspector.h>

// GLOBAL VARIABLES 

// Options (default)

bool outputf = false;
int log_type=LOG_APACHE;	// APACHE format by default 
int rule_type=0;			// Snort rules by default
bool nocase = false;
bool ealert = false;
bool warns = false;
bool resp_code = false;
bool rules_snort = false;
bool rules_nem = false;
bool uri_labels = false;

// Files/Input/Output

unsigned char log_path[PATH_MAX+1];
unsigned char rules_path_snort[PATH_MAX+1];
unsigned char rules_path_nem[PATH_MAX+1];
unsigned char output_file[PATH_MAX+1];

// Counters

int num_rules[NSIDS+1];                       
int num_URIrules[NSIDS+1];                    
int num_errorrules[NSIDS+1];                  
int num_rules_file;

// Rules

URI_rule * URI_rules[MAX_URI_RULES];

int debug;

#ifdef DEBUGTIME
time_t rawtime;
struct tm *timeinfo;
#endif

struct timespec tp;
long begin, end;
long time_spent;

// Free memory (rules)

void free_all(){
    for(int i=0; i<num_URIrules[0]; i++){
        free_rule(URI_rules[i]);
    }
}

/* Cronometer: start /end  */

void time_start(){

    if(clock_gettime(CLOCK_REALTIME, &tp) == 0){
        begin = tp.tv_nsec;
    } else {
        printf("[time_start] Error in 'time_start()': Could not get current time\n");
    }
}

void time_end(){

    if(clock_gettime(CLOCK_REALTIME, &tp) == 0){
        end = tp.tv_nsec;
        time_spent = end-begin;
        printf("# Execution time: %f s\n", ((float)abs(time_spent))/1000000000.0);
    } else {
        printf("[time_end] Error in 'time_end()': Could not get end time\n");
    }
}

/************************************************/
/* Memory management                            */
/************************************************/

unsigned char * uchar_malloc(int num_bytes){

    unsigned char * ptr;

    ptr = (unsigned char*) malloc(num_bytes);
    if (ptr == NULL){
        printf("[Memory] Error in 'uchar_malloc': Memory reservation failure \n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

/************************************************/
/* MAIN PROGRAM                          */
/************************************************/

int main(int argc, char **argv){

	//For time measure
    time_start();

    //Set function to be executed on exit
    if( atexit(free_all) != 0){
        printf("[%s] Error in 'main program': Error at 'atexit' invocation\n",argv[0]);
    }

    //Default arguments
    strncpy(rules_path_snort, RULES_DIR, PATH_MAX);
    
    printf("# inspectorlog %s\n",INSPECTOR_VER);;

#ifdef DEBUG
    printf("> Processing start\n");
#endif
    
    //Parse command line arguments
    if( !parse_clArgs(argc, argv))
        exit(EXIT_FAILURE);

#ifdef DEBUG
    printf("> Arguments read ...\n");
#endif

    // Rules loading 

	if (!rules_snort && !rules_nem) rules_snort = true;  // Snort rules by default

    if (rules_snort) load_rules_snort(rules_path_snort);
#ifdef DEBUG
    printf("> [SNORT RULES] Loaded [%d] util rules from [%d] total ...\n", num_URIrules[SNORT], num_rules[SNORT]);
#endif
    
    if (rules_nem) load_rules_nemesida(rules_path_nem);
#ifdef DEBUG
    printf("> [SNORT NEM] Loaded [%d] util rules from [%d] total ...\n", num_URIrules[SNORT], num_rules[SNORT]);
#endif
   	
	// If rules from snort and nemesida, print overall rules' statistics
	
	if (rules_snort && rules_nem) {	
		printf("#----- Statistics (OVERAL) ----------------------------\n");
		printf("# Read [%d] nemesida rules, [%d] http-related, [%d] with errors\n", num_rules[0], num_URIrules[0], num_errorrules[0]);
	};
	printf("#----- Analysis results ----------------------------\n");
	
    printf("# Alerts & signatures generated from: %s", argv[0]);
    for (int i=1; i < argc; i++) printf(" %s",argv[i]);
    printf("\n");
    
    // Read and process log file 
    
#ifdef DEBUTIME
    time(&rawtime); 
#endif

    scan_logFile(log_path);

    //For time measure
    time_end();

    return 0;
}
