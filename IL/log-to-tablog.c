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
** log-to-tablog
** Reads any of the supported input formats and outputs a tab separated fields format
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
#include <getopt.h>

//INSPECTORLOG INCLUDES
#include <inspector-common.h>
#include <inspector.h>

// GLOBAL VARIABLES 

// Options (default)

bool outputf = false;
int log_type=LOG_APACHE;	// APACHE format by default 
bool uri_labels = false;
bool resp_code = false;
bool separa_query = false;

// Unneeded variables (compatibility with header) 

bool nocase;
bool ealert;
bool warns;
int nlineas;
time_t rawtime;
struct tm *timeinfo;

// Files/Input/Output

unsigned char log_path[PATH_MAX+1];
unsigned char output_file[PATH_MAX+1];

bool clArgs(int argc, char **argv){

    bool isOK = true;

    int c;

    if(argc < 3) {
		printf("FORMAT: log-to-tablog -l logFile [-t <list|elist|apache|wellness|uri>] [-c (response code filtering)] [-b (labeled uris)] [-q (split path/query)]\n");

		exit(EXIT_SUCCESS);	
	}
    while (1){

        static struct option long_options[] =
             {
               /* These options don't set a flag.
                  We distinguish them by their indices. */
               {"log_file",  required_argument, 0, 'l'},
               {"logtype", required_argument, 0, 't'},
               {"output", required_argument, 0, 'o'},
			   {"resp_code", no_argument, 0, 'c'},
			   {"labels", no_argument, 0, 'b'},
 			   {"query", no_argument, 0, 'q'},
			   {0, 0, 0, 0}
             };
           /* getopt_long stores the option index here. */
           int option_index = 0;

        c = getopt_long(argc, argv, "l:t:ocbq", long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

#ifdef DEBUG
            printf("Option detected %c, %s\n",c,optarg);
#endif        
        switch (c){

            case 'l':
                //printf ("option -l with value '%s'\n", optarg);
                strncpy((char*)&log_path, optarg, PATH_MAX);
                break;
            case 't':
                if (!strcmp(optarg,"list")) {
                    log_type = LOG_LIST;
                } else if (!strcmp(optarg,"apache")) {
                    log_type = LOG_APACHE;
                } else if (!strcmp(optarg,"wellness")) {
                    log_type = LOG_WELLNESS;
                } else if (!strcmp(optarg,"uri")) {
                    log_type = LOG_URI;
				} else if (!strcmp(optarg,"elist")) {
					log_type = LOG_ELIST;
                } else {
                    printf("log-to-tablog: log format [%s] not recognized\n",optarg);
                    exit(-1);
                }
                break;
            case 'o':
                strncpy((char *)&output_file, optarg, PATH_MAX);
                outputf = true;
                break;
			case 'c':
				resp_code = true;
				break;
			case 'q':
				separa_query = true;
				break;
			case 'b':
				uri_labels = true;
            default:
				printf("FORMAT: log-to-tablog -l logFile [-t <list|elist|apache|wellness|uri>] [-c (response code filtering)] [-b (labeled uris)]  [-q (split path/query)]\n");
				exit(EXIT_SUCCESS);
		}
    }
#ifdef DEBUG
    printf(">> Command line arguments processed ...\n");
#endif

    /* Print any remaining command line arguments (not options). */
    if (optind < argc){
           printf ("[parse_clArgs] Argument(s) erroneous: ");
           while (optind < argc)
             printf ("%s ", argv[optind++]);
           putchar ('\n');
    }

    return isOK;
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

	char query[URILENGTH];
	char time[WORDLENGTH];
	char method[WORDLENGTH];
	char prot[WORDLENGTH];
	char *q;
	char *logLine;
	int lineLength;
	log_map map;
	int tmp, parsed;
	ssize_t read;
	int npackets;
	
    //Default arguments

#ifdef DEBUG
    printf("> Processing start\n");
#endif
    
    //Parse command line arguments
    if( ! clArgs(argc, argv))
        exit(EXIT_FAILURE);

#ifdef DEBUG
    printf("> Arguments read ...\n");
#endif

    // Input / output files

    FILE * logFile = fopen(log_path, "r");
	FILE *fout;
    Apache_logEntry logEntry;

    if(logFile != NULL){

        logLine = (char*) malloc (sizeof(char)*MAXLOG_LINE);
		lineLength = MAXLOG_LINE*sizeof(char);

        // Initialize log map

        init_log_map(&map);

        if (outputf) {
#ifdef DEBUG
            printf("Opening clean output file <%s>\n",output_file);
#endif
            fout = fopen(output_file,"w");
            if (!fout) {
                printf("[scan_logFile]: ERROR - Opening output file [%s]\n",output_file);
                exit(-1);
            }
#ifdef DEBUG
            printf(" ... Done \n");
#endif
        } else fout = stdout;
		
        // Read first line (# of URIS) in an LOG_URI type
        if (log_type == LOG_URI) {
			read = getline(&logLine, &lineLength, logFile);

			// Write in the header the number of lines (maximum is the read value) - 1M lines top (output formatting)

			tmp = sscanf(logLine,"%d\n",&npackets);
			if (tmp != 1) {
                printf("[scan_logFile]: ERROR reading the number of lines [%s]\n",output_file);
                exit(-1);
			}
			if (outputf) fprintf(fout,"%8d\n",npackets);
			nlineas = 1;
    	} else nlineas = 0;

        // Read and process each line

        for(int i=1; (read = getline(&logLine, &lineLength, logFile)) != -1; i++) {

 			if (read > MAXLOG_LINE) {
					printf("[scan_LogFile]: WARNING - Line [%d] too long (%d chars) - DISMISSED\n", nlineas, read);
					continue;
			}
			read++;		// To count for '\0'
            nlineas++;

            // Line parsing

            init_Apache_logEntry(&logEntry);

            if ((log_type == LOG_APACHE) || (log_type == LOG_WELLNESS)) parsed = parse_apache_logEntry(logLine, &logEntry, map, read);
			else if (log_type == LOG_URI) parsed = parse_uri_logEntry(logLine, &logEntry, map, read) ;
			else if (log_type == LOG_LIST) parsed = parse_list_logEntry(logLine, &logEntry, map, read);
			else if (log_type == LOG_ELIST) parsed = parse_elist_logEntry(logLine, &logEntry, map, read);
			if (parsed == -1) {
//				npackets ++;
				continue;
			};

			if ((resp_code) && (logEntry.status_code >= RESP_CODE_INVALID) ) continue;
			
			// Print output 
			
			if (separa_query) {
				q = strchr(logEntry.URI,'?'); 
				if (q) {
					strcpy(query,q+1);
					logEntry.URI[q-logEntry.URI]='\0';
				} else {
					query[0] = '\0';
				}
			};
			
			if ((log_type == LOG_APACHE) || (log_type == LOG_WELLNESS) || (log_type == LOG_ELIST)) {
				if (logEntry.request_method == GET) strcpy(method,"GET");
				else if (logEntry.request_method == POST) strcpy(method,"POST");
				else if (logEntry.request_method == HEAD) strcpy(method,"HEAD");
				else if (logEntry.request_method == PROPFIND) strcpy(method,"PROPFIND");
				else if (logEntry.request_method == PUT) strcpy(method,"PUT");
				else if (logEntry.request_method == NONE) strcpy(method,"NONE");
				else {
						printf("[log-to-tablog: ERROR unknown method in line [%d]\n",nlineas);
						exit(-1);
				}
			}
			
			if (logEntry.Protocol == _1_0) strcpy(prot,"HTTP/1.0\"");
			else if (logEntry.Protocol == _1_1) strcpy(prot,"HTTP/1.1\"");
			else strcpy(prot,"");
			
			if (uri_labels) fprintf(fout,"%s\t",logEntry.label);
			if (log_type == LOG_APACHE) {
				strftime(time,WORDLENGTH,"[%d/%b/%Y:%T%z]",&logEntry.time);
				fprintf(fout,"%s\t%s\t%s\t%s\t%s\t",logEntry.ip_address,logEntry.user_identifier,logEntry.user_id,time,method,logEntry.URI);
				if (separa_query) {
					if (query[0] != '\0') fprintf(fout,"%s\t",query);
					else fprintf(fout,"\t");
				};
				fprintf("%s\t%d\t%d\t%s\t%s\n",prot,logEntry.status_code,logEntry.return_size,logEntry.referer,logEntry.user_agent);
				
			} else if (log_type == LOG_WELLNESS) {				
				fprintf(fout,"TODO\n");
			} else if (log_type == LOG_URI) {
				fprintf("%d\t%s",strlen(logEntry.URI),logEntry.URI);
				if (separa_query) {
					if (query[0] != '\0') fprintf(fout,"%s\n",query);
					else fprintf(fout,"\t\n");
				};									
			} else if (log_type == LOG_LIST) {
				fprintf("%s",logEntry.URI);
				if (separa_query) {
					if (query[0] != '\0') fprintf(fout,"%s\n",query);
					else fprintf(fout,"\t\n");
				};	
			} else if (log_type == LOG_ELIST) {
				fprintf("%s\t%s",method,logEntry.URI);
				if (separa_query) {
					if (query[0] != '\0') fprintf(fout,"%s\t",query);
					else fprintf(fout,"\t");
				};	
				fprintf("%s\t%d\t%d\n",prot,logEntry.status_code,logEntry.return_size);
			};
			
		};
		
	
		// Cleaning 
		
	    free(logLine);
        fclose(logFile);
		if (outputf) fclose(fout);

    } else {
        printf("[log-to-tablog]: ERROR - Log path is incorrect = %s\n", log_path);
    }

    return 0;
}
