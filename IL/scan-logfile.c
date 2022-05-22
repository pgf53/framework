/*
** INSPECTORLOG
** Todos los derechos reservados
** All rights reserved
**
** Copyright (C) 2017, Jesús E. Díaz Verdejo
** Versión 3.4 JEDV - 25/11/2021
** Versión 3.0 JEDV - 19/12/2017
**
** Changes:
**
**   v3.4: Differentiated management of list and URI log types, including optional response code
**   v3.4: Optional labels for log entries
**   v3.4: Authomatic discard of not recognized methods (only Apache like logs)
**   v3.4: Considering NULL CHAR as potential part of a URI by explicitly using URI length - TODO: Not really used during comparison (engine)
**   v3.4: Added extended list format
*/

//INSPECTORLOG INCLUDES

#include <inspector-common.h>
#include <inspector.h>

int nlineas = 0;

/****************************/
/* Public routines (inspectorlog)          */
/****************************/

/* Line by line analysis of a log file          */
/* Standard output is screen - Alerts are printed to screen */

void scan_logFile(const char *fileName ){

	int total_alertas = 0;
	int npackets = 0;
	int npackets_with_alerts = 0;
	int n_nem_alerts = 0, n_alerts = 0;
	struct log_map map;
	int tmp, n, s, parsed;
	int total_score = 0;
	bool wlr;


	//   char logLine[MAXLOG_LINE];
	char * logLine;
	char out_logline[MAXLOG_LINE];
	size_t lineLength;
	ssize_t read;

    //open file
    FILE * logFile = fopen(fileName, "r");
    FILE *fout;
    Apache_logEntry logEntry;
    int rules_detected[MAX_ALERTS_PER_URI], sid_detected[MAX_ALERTS_PER_URI], sid_sorted[MAX_ALERTS_PER_URI]; /* Lists of alerts triggered for a log line  */
	int scores[MAX_ALERTS_PER_URI];
	char *messages_detected[MAX_ALERTS_PER_URI]; /* Pointer to descriptions for sorted output */

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
        };

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
			npackets = 0;
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

            if (outputf) memcpy(out_logline,logLine,sizeof(char)*read);		// Copy original logline for output
            if ((log_type == LOG_APACHE) || (log_type == LOG_WELLNESS)) parsed = parse_apache_logEntry(logLine, &logEntry, map, read);
			else if (log_type == LOG_URI) parsed = parse_uri_logEntry(logLine, &logEntry, map, read) ;
			else if (log_type == LOG_LIST) parsed = parse_list_logEntry(logLine, &logEntry, map, read);
			else if (log_type == LOG_ELIST) parsed = parse_elist_logEntry(logLine, &logEntry, map, read);
			if (parsed == -1) {
//				npackets ++;
				continue;
			};

            /* ---------- INDIVIDUAL RULES ----------
                Rules are invididually applied to each of the log records
				Only current record is considered
            */

			if ((resp_code) && (logEntry.status_code >= RESP_CODE_INVALID) ) continue;

            // Detect attack patterns in URI

			// Initialization
            int pos_matches = 0; 			//Number of positive matches via Individual Rules Scan
            for (int j=0; j < MAX_ALERTS_PER_URI; j++) { rules_detected[j]=0; sid_detected[j]=0; };

            npackets ++;
#ifdef DEBUGTIME
            time(&rawtime);
            printf("Parsing packet [%d]= \"%s\"", i, ctime(&rawtime));
#endif
			// Detection
			// TODO: Compare all the string (even with \0 inside)

            pos_matches = detect_URI(logEntry.URI, rules_detected);
            if (pos_matches > 0 ){ 		// Alerts triggered

                // Prepare to order alerts by SID

                for (n= 0; n< pos_matches;n++) {
					sid_detected[n] = URI_rules[rules_detected[n]]->sid;
					sid_sorted[n] = sid_detected[n];
				}

				// Handle nemesida scores - Check if total score is greater than threshold

				n_nem_alerts = 0;
				total_score = 0;
				wlr = false;
				for(n=0; n < pos_matches; n++){
					if (sid_detected[n] > NEMESIDA_OFFSET) {
						s = URI_rules[rules_detected[n]]->score;
						n_nem_alerts ++;
						if (s == 0) {
							wlr = true;
						} else {
							total_score += s;
						};
					};
				};
				if (wlr) total_score = 0;

                // Order alerts by SID

                qsort(sid_sorted, pos_matches, sizeof(unsigned int), compare);
				for (s=0; s < pos_matches; s++) {
					for (n = 0; n < pos_matches; n++) {
						if (sid_sorted[s] == sid_detected[n]) {
							messages_detected[s] = URI_rules[rules_detected[n]]->description;
							scores[s] = URI_rules[rules_detected[n]]->score;
						};
						continue;
					};
				};

				// Check if there are alerts to print

				if (total_score < SCORE_THD) n_alerts = pos_matches - n_nem_alerts;
				else n_alerts = pos_matches;
				
				if (n_alerts > 0) {  // There are remaining alerts after scoring

					// Alerts triggered: print output - u2uri compatible format

					if (uri_labels) {
						printf("Packet [%d]%s\tUri [%s]\tNattacks [%u]\tSignatures", i, logEntry.label,logEntry.URI, n_alerts);

					} else {
						printf("Packet [%d]\tUri [%s]\tNattacks [%u]\tSignatures", i, logEntry.URI, n_alerts);
					};
					total_alertas += n_alerts;

					// Ouput attacks information

					for(int n=0; n<pos_matches; n++){

						if (ealert) {
							s = sid_sorted[n];
							if ((s < NEMESIDA_OFFSET) || (total_score >= SCORE_THD) ) {
								printf("\t[%s - SC %d - sid: %u]",messages_detected[n],scores[n],s);
							};
						} else if ((s < NEMESIDA_OFFSET) || (total_score >= SCORE_THD))
							printf("\t[%u]",sid_sorted[n]);

					}
					printf("\n");
					npackets_with_alerts++;
				} else {	// Packet with void alerts - Print clean log if needed
					if (outputf) fprintf(fout,"%s",out_logline);
				};
            } else if (outputf) {
                fprintf(fout,"%s",out_logline);
            }

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
    } else {
        printf("[scan_logFile]: ERROR - Log path is incorrect = %s\n", fileName);
    }
}


