/*
** INSPECTORLOG
** Todos los derechos reservados
** All rights reserved
**
** Copyright (C) 2017, Jesús E. Díaz Verdejo
** Version 3.5 JEDV - 24/02/2020
** Versión 3.4 JEDV - 25/11/2021
** Versión 3.0 JEDV - 19/12/2017
**
** Changes:
**   v3.5: Problems when '"]' appears inside some field values e.g. [data "Matched Data: ,"values":["CM049 - Urb. La Pastora"]}] found within ARGS:filters: [{"attr_type":"602","values":["CM049 - Urb. La Pastora"]}]"] -> Solved searching for '"] ' or '"]\n'
**   v3.5: Added PUT method
**   v3.5: Incorporated as part of inspectorlog toolset (adapted ...)
**   v3.4: Differentiated management of list and URI log types, including optional response code
**   v3.4: Optional labels for log entries
**   v3.4: Authomatic discard of not recognized methods (only Apache like logs)
**   v3.4: Considering NULL CHAR as potential part of a URI by explicitly using URI length - TODO: Not really used during comparison (engine)
**   v3.4: Added extended list format
*/

//INSPECTORLOG INCLUDES

#include <inspector-common.h>
#include <ms-inspector.h>

#undef DEBUG 
#undef DEBUG2

FILE *mslog;						// Log file (direct output)
int nlineas = 0;
bool anomaly = false;

/**********************************/
/* Log and alert parsing function */
/**********************************/

void clean_alerts() {
	int n;
	
	for (n=0; n < nalerts; n++) {
		ms_alerts[n].file[0] = '\0';
		ms_alerts[n].line = -1;
		ms_alerts[n].id = -1;
		ms_alerts[n].rev[0] = '\0';
		ms_alerts[n].msg[0] = '\0';
		ms_alerts[n].data[0] = '\0';
		ms_alerts[n].severity = 0;
		ms_alerts[n].ver[0] = '\0';
		ms_alerts[n].maturity = 0;
	    ms_alerts[n].accuracy = 0;
		ms_alerts[n].tag[0] = '\0';
		ms_alerts[n].hostname[0] = '\0';
		ms_alerts[n].uri[0] = '\0';
		ms_alerts[n].unique_id[0] = '\0';
		ms_alerts[n].ref[0] = '\0';
	};
	return;
}


void msc_logdata(void *log, const void *data) {

	ModSec_alert *alert;		// Current alert
	char *p, *q, *r;			// Auxiliary pointers to start, keywords and end of each item
	int l, n;
	bool notfound;
	char tmp[URILENGTH];		// Temporary storage of item

	if (data != NULL) {

		if (mslogfile) fprintf(mslog,"LINEA [%d] --- %s\n",nlineas,data);
		
		// Parsing log line 
	
		if (strstr(data,"TX:ANOMALY_SCORE")) {		// Threshold exceeded alert -> URI is anomalous
			anomaly = true;
			return;
		}

		if (true) { 
			if (nalerts >= MAX_MSALERTS) {
				fprintf("msc_logdata] WARNING: Maximum number of alerts per URI exceeded - line [%d]\n",nlineas);
				return;
			};
			// TODO: Check for selected alerts 
			// (strstr(data,"REQUEST_URI") || strstr(data,"detected SQLi") || strstr(data,"REQUEST_FILENAME")){
			p = data;
			alert = &ms_alerts[nalerts];
			p = strstr(data,"[file");		// It is assumed that the first field is [file ]
			if (p == NULL) {
				printf("[msc_logdata] ERROR: Cannot find FILE field in log line\n");
				return;
			}
			r=p;
			while (p = strchr(r,'[')) {
//				printf("Parsing %s\n",p);
				p++;
				q = strchr(p,' ');
				if (q == NULL) {
					printf("[msc_logdata] Error parsing log line [%s]\n",data);
					exit(-1);
				};
				r = strchr(q+1,'"');
				if (r == NULL) {
					printf("[msc_logdata] Error parsing log line [%s]\n",data);
					exit(-1);
				};
				
			// Search for '"] ' as end of field to avoid problems with literal ] inside URI and complex fields (e.g. '"]}' in some rules -> LIMITATION: Literal '"] ' generates a parse error
				notfound = true;
				while ((notfound) && (r)) {
					if ((*(r+1) == ']') && ((*(r+2) == ' ') || (*(r+2) == '\n') || (*(r+2) == '\0'))) {
						notfound = false;
						r++;
					} else {
						r = strchr(r+1,'"');
						if (r == NULL) {
							printf("[msc_logdata] Error parsing log line - end of field [%s]\n",p);
							exit(-1);
						};
					};
				};
				
				l = q-p;
				q+=2;
				n = r-q-1;
				strncpy(tmp,p,l);
				tmp[l]= '\0';
				if (n > 0) {
					if (!strncmp(p,"file",l)) {
						strncpy(alert->file,q,n);
						alert->file[n] = '\0';
#ifdef DEBUG2
						printf("FILE -> %s\n",alert->file);
#endif
					} else if (!strncmp(p,"line",l)) {
						sscanf(q,"%d",&alert->line);
#ifdef DEBUG2
						printf("LINE -> %d %s\n",alert->line,tmp);
#endif
					} else if (!strncmp(p,"id",l)) {
						sscanf(q,"%d",&alert->id);					
#ifdef DEBUG2
						printf("ID -> %d\n",alert->id);
#endif
					} else if (!strncmp(p,"rev",l)) {
						strncpy(alert->rev,q,n);
						alert->rev[n] = '\0';
#ifdef DEBUG2
						printf("REV -> %d \n",alert->rev);					
#endif
					} else if (!strncmp(p,"msg",l)) {
						strncpy(alert->msg,q,n);
						alert->msg[n] = '\0';					
#ifdef DEBUG2
						printf("MSG -> %s \n",alert->msg);					
#endif
					} else if (!strncmp(p,"data",l)) {
						strncpy(alert->data,q,n);
						alert->data[n] = '\0';					
#ifdef DEBUG2
						printf("DATA -> %s \n",alert->data);					
#endif
					} else if (!strncmp(p,"severity",l)) {
						sscanf(q,"%d",&alert->severity);					
#ifdef DEBUG2
						printf("SEV -> %d \n",alert->severity);					
#endif
					} else if (!strncmp(p,"ver",l)) {
						strncpy(alert->ver,q,n);
						alert->ver[n] = '\0';
#ifdef DEBUG2
						printf("VER -> %s \n",alert->ver);					
#endif
					} else if (!strncmp(p,"maturity",l)) {
						sscanf(q,"%d",&alert->maturity);
#ifdef DEBUG2
						printf("MATURITY -> %d \n",alert->maturity);					
#endif
					} else if (!strncmp(p,"accuracy",l)) {
						sscanf(q,"%f",&alert->accuracy);
#ifdef DEBUG2
						printf("ACC -> %f \n",alert->accuracy);					
#endif
					} else if (!strncmp(p,"tag",l)) {
						strcat(alert->tag," ");
						strncat(alert->tag,q,n);
#ifdef DEBUG2
						printf("TAG -> %s \n",alert->tag);					
#endif
					} else if (!strncmp(p,"hostname",l)) {
						strncpy(alert->hostname,q,n);
						alert->hostname[n] = '\0';
#ifdef DEBUG2
						printf("HOST -> %s \n",alert->hostname);					
#endif
					} else if (!strncmp(p,"uri",l)) {
						strncpy(alert->uri,q,n);
						alert->uri[n] = '\0';
#ifdef DEBUG2
						printf("URI -> %s \n",alert->uri);					
#endif
					} else if (!strncmp(p,"unique_id",l)) {
						strncpy(alert->unique_id,q,n);
						alert->unique_id[n] = '\0';
#ifdef DEBUG2
						printf("UID -> %s \n",alert->unique_id);					
#endif
					} else if (!strncmp(p,"ref",l)) {
						strncpy(alert->ref,q,n);
						alert->ref[n] = '\0';
#ifdef DEBUG2
						printf("REF -> %s \n",alert->ref);					
#endif
					} else {
						printf("ERROR->[%s]\n",p);
						printf("[msc_logdata] WARNING: Unknown field in log line [%s]\n",data);
					}			
				};
			}
			nalerts++;
		} else {
			printf("[msc_logdata] Not URI related alert\n");
		};
	};
#ifdef DEBUG
	printf("LOG DATA: [%d] L[%d] ID[%d] S[%d] U[%s] UID[%s]\n",nalerts-1,alert->line,alert->id,alert->severity,alert->uri,alert->unique_id);
#endif
    return;
}

/* Line by line analysis of a log file          */
/* Standard output is screen - Alerts are printed to screen */

void ms_scan_logFile(const char *fileName ){

	int total_alertas = 0;
	int npackets = 0;
	int npackets_with_alerts = 0;
	int n_alerts = 0;
	struct log_map map;
	int tmp, n, s, parsed;
	int rc;
	char *p;

	char * logLine;
	char out_logline[MAXLOG_LINE];
	int paranoialevel;
	size_t lineLength;
	ssize_t read;

    //open file
    FILE * logFile = fopen(fileName, "r");
    FILE *fout;
    Apache_logEntry logEntry;

    if(logFile != NULL){

        logLine = (char*) malloc (sizeof(char)*MAXLOG_LINE);
		lineLength = MAXLOG_LINE*sizeof(char);

        // Initialize log map

        init_log_map(&map);

		if (mslogfile) {
			mslog = fopen(outputms_file,"w");
			if (!mslog) {
				printf("[ms_scan_logFile]: ERROR - Opening modsecurity log output file [%s]\n",outputms_file);
				exit(-1);
			}
		}
		
        if (outputf) {
#ifdef DEBUG
            printf("Opening clean output file <%s>\n",output_file);
#endif
            fout = fopen(output_file,"w");
            if (!fout) {
                printf("[ms_scan_logFile]: ERROR - Opening output file [%s]\n",output_file);
                exit(-1);
            }
#ifdef DEBUG
            printf(" ... Done \n");
#endif
        };


        // Read first line (# of URIS) in an LOG_URI type
        if (log_type == LOG_URI) {
			read = getline(&logLine, &lineLength, logFile);

			// Write in the header the number of lines (maximum is the read value) - 1M lines top (output formatting)

			tmp = sscanf(logLine,"%d\n",&npackets);
			if (tmp != 1) {
                printf("[ms_scan_logFile]: ERROR reading the number of lines [%s]\n",output_file);
                exit(-1);
			}
			if (outputf) fprintf(fout,"%8d\n",npackets);
			npackets = 0;
			nlineas = 1;
    	} else nlineas = 0;

        // Read and process each line

        for(int i=1; (read = getline(&logLine, &lineLength, logFile)) != -1; i++) {

 			if (read > MAXLOG_LINE) {
					printf("[ms_scan_LogFile]: WARNING - Line [%d] too long (%d chars) - DISMISSED\n", nlineas, read);
					continue;
			}
			read++;		// To count for '\0'
            nlineas++;

            // Line parsing

            init_Apache_logEntry(&logEntry);

            if (outputf) memcpy(out_logline,logLine,sizeof(char)*read);		// Copy original logline for output
            if ((log_type == LOG_APACHE) || (log_type == LOG_WELLNESS)) parsed = parse_apache_logEntry(logLine, &logEntry, map, read);
			else if (log_type == LOG_URI) parsed = parse_uri_logEntry(logLine, &logEntry, map, read) ;
			else if (log_type == LOG_LIST) parsed = parse_list_logEntry(logLine, &logEntry, map, read);
			else if (log_type == LOG_ELIST) parsed = parse_elist_logEntry(logLine, &logEntry, map, read);
			if (parsed == -1) {
				continue;
			};

			if ((resp_code) && (logEntry.status_code >= RESP_CODE_INVALID) ) continue;


			// For the time being, only uri and method are considered. The rest of the fields are fixed
			// TODO: Process aditional fields in the request if available
			
#ifdef DEBUG	
			printf("Leido: [%s]\n",logLine);
#endif
#ifdef DEBUGTIME
            time(&rawtime);
            printf("Parsing packet [%d]= \"%s\"", i, ctime(&rawtime));
#endif
            npackets ++;
		
			/* Transaction creation */

			Transaction *trans = msc_new_transaction(modsec, rules, msc_logdata);		// Transaction container
			if (trans == NULL) {
				fprintf(stderr, "[ms-inspectorlog] Initialization error \n");
				exit(-1);
			}
		
			/* First pass: URI as is */

			rc = msc_process_connection(trans, "127.0.0.1", i % 32500, "127.0.0.1", 80);
			
			// Set some header fields required by CRS OWASP rules 
			
			msc_add_request_header(trans, (unsigned char *)"Host", (unsigned char *)"localhost");
			msc_add_request_header(trans, (unsigned char *)"User-Agent", (unsigned char *)"Apache/2.2.15 (Red Hat) (internal dummy connection)");
			msc_add_request_header(trans, (unsigned char *)"Accept", (unsigned char *)"Yes");
			msc_append_request_body(trans, (unsigned char *)"", 0);
			if (map.method >= 0 ) {
				if (logEntry.request_method == GET)
					rc = msc_process_uri(trans, logEntry.URI, "GET", "1.1"); 
				else if (logEntry.request_method == POST)
					rc = msc_process_uri(trans, logEntry.URI, "POST", "1.1"); 
				else if (logEntry.request_method == HEAD)
					rc = msc_process_uri(trans, logEntry.URI, "HEAD", "1.1"); 
				else if (logEntry.request_method == PROPFIND)
					rc = msc_process_uri(trans, logEntry.URI, "PROPFIND", "1.1"); 
				else if (logEntry.request_method == PUT)
					rc = msc_process_uri(trans, logEntry.URI, "PUT", "1.1"); 
				
			} else {
				rc = msc_process_uri(trans, logEntry.URI, "GET", "1.1"); 
			}
			
			rc = msc_process_request_headers(trans);

			rc = msc_process_request_body(trans);			
/*
			msc_process_response_headers(trans, 200, "1.1");
			msc_process_response_body(trans);
*/
			msc_process_logging(trans);

			// TODO: keep analyzing while percent encoding 
			
			// TODO: Check for duplicated alerts

			// Triggered alerts processing -> If anomaly mode is considered in CRS, an alert is rised when the threshold is surpassed -> No need to handle threshold
			// WARNING: Problem with trigger and duplicated alerts 
			
#ifdef DEBUG2
			printf("DETECTED\n");
			for (n=0;n<nalerts;n++) {
					printf("[%d] L[%d] ID[%d] S[%d] U[%s] UID[%s]\n",n,ms_alerts[n].line,ms_alerts[n].id,ms_alerts[n].severity,ms_alerts[n].uri,ms_alerts[n].unique_id);
			}
#endif

			// Postprocess alerts 

			if ((nalerts > 0) && (anomaly)) { 	 		// Alerts triggered

				// TODO: Scoring process (if needed)
				
				if (nalerts > 0) {  // There are remaining alerts after scoring

					// Alerts triggered: print output - u2uri compatible format

					if (uri_labels) {
						printf("Packet [%d]%s\tUri [%s]\tNattacks [%u ]\tSignatures", i, logEntry.label,logEntry.URI, nalerts);

					} else {
						printf("Packet [%d]\tUri [%s]\tNattacks [%u ]\tSignatures", i, logEntry.URI, nalerts);
					};
					total_alertas += nalerts;

					// Ouput attacks information

					for(int n=0; n< nalerts; n++){

						if (ealert) {
							paranoialevel = 0;
							if (p = strstr(ms_alerts[n].tag,"paranoia-level/")) {
								sscanf(p+15,"%d",&paranoialevel);
							}								
							printf("\t[%s - PL%d - SC %d - sid: %u]",ms_alerts[n].msg,paranoialevel, ms_alerts[n].severity,ms_alerts[n].id);
						} else {
							printf("\t[%u]",ms_alerts[n].id);
						};
					}
					printf("\n");
					npackets_with_alerts++;
				} else {	// Packet with void alerts - Print clean log if needed
					if (outputf) fprintf(fout,"%s",out_logline);
				};
            } else if (outputf) {	// Packet without alerts - Print clean log if needed
                fprintf(fout,"%s",out_logline);
            }
			
			// Clear alerts / transaction for next line

			msc_transaction_cleanup(trans);
			clean_alerts();
			nalerts = 0;
			anomaly = false;

        }

        if (outputf) {
			if (log_type == LOG_URI) {	// If LOG_URI type, adjust the number of registers (1st line)
				rewind(fout);
				fprintf(fout,"%8d\n",npackets-npackets_with_alerts);
			};
			fclose(fout);
        };

		// Final summary for all the records - u2uri compatible

        printf("# N. packets [%d], [%d] with alerts, N. Alerts [%d]\n",npackets, npackets_with_alerts, total_alertas);

        free(logLine);
	    fclose(logFile);

		if (mslog) fclose(mslog);

    } else {
        printf("[ms_scan_logFile]: ERROR - Log path is incorrect = %s\n", fileName);
    }
}
