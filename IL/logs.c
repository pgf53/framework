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
** Changes:
**
**   v3.5: Added PUT method as valid for processing
**   v3.4: Differentiated management of list and URI log types, including optional response code
**   v3.4: Optional labels for log entries
**   v3.4: Authomatic discard of not recognized methods (only Apache like logs)
**   v3.4: Considering NULL CHAR as potential part of a URI by explicitly using URI length - TODO: Not really used during comparison (engine)
**   v3.4: Added extended list format
*/

//INSPECTORLOG INCLUDES

#include <inspector-common.h>

extern int nlineas;

/****************************/
/* Auxiliary routines       */
/****************************/

/************************************************/
/*  IP handling functions                       */
/************************************************/

//Convert ip from string to 4 bytes representation
void convert_ipv4(const char ip_string[16], unsigned char ip_byte[4]){

    char * token = strtok((char *)ip_string, ".");
    for (int n=0; n<4; n++) {
        int tmp = atoi(token);
        ip_byte[n] = (unsigned char)tmp;
#ifdef DEBUG
        printf ("%s\n", token);
#endif
        token = strtok(NULL, ".");
    }
}

unsigned int dec_toIP(unsigned char ip_address[4]){

    unsigned int IP = 0;
    IP |= (ip_address[0] << 24 );
    IP |= (ip_address[1] << 16 );
    IP |= (ip_address[2] <<  8 );
    IP |= (ip_address[3]       );

    return IP;
}

// Initialization of mapping of fields from log file

void init_log_map(log_map *m ) {

   /* Field mapping (dependent on the log type) - OPTIONAL LABEL */
    /* TYPE WELLNESS (10 fields)
    2017-06-22T06:25:15.356441+02:00 A-SQU-BAL-HAP03 haproxy[5518]: 10.128.2.64:46469 {www.wtelecom.es} "GET / HTTP/1.1" main_http_frontend WT_www_be/A-WTE-INF-WEB03
    TIMESTAMP NODE PLACE IP:PORT {server} "METHOD URI VER" CODE1 CODE2

    TYPE APACHE (12 fields)
    172.16.16.210 - - [02/May/2017:12:21:07 +0200]  "GET http://127.0.0.1/finger HTTP/1.1" 404 289 "-" "Wget/1.17.1 (linux-gnu)"
    37.152.139.155 - - [07/Nov/2013:17:00:31 -0800] "GET /2003/padron.html HTTP/1.1" 200 11800 "-" "Java/1.7.0_15" "ajedreznd.com"
    IP USERIDENTIFIER USERID [TIMESTAMP DIF] "METHOD URI PROTOCOL" CODE1 CODE2 "-" "REFERER"

    TYPE LIST (1 field)
	(URI in the first field)

	TYPE URI (2 fields)
	(URI in the second field -first line contains the total number of registers

	TYPE ELIST (5 fields)
	GET /ingenieros/node HTTP/1.1" 200 26091
	
	OPTIONAL LABEL (FIRST FIELD []) IN ALL FORMATS

    */

    if (log_type == LOG_APACHE) {
        m->ip = 0;
        m->useridentifier = 1;
        m->userid = 2;
        m->timestamp = 3;
        m->dif = 4;
        m->method = 5;
        m->uri = 6;
        m->protocol = 7;
        m->status_code = 8;
        m->return_size = 9;
        m->referer = 10;
        m->user_agent=11;
		m->nfields = 12;
    } else if (log_type == LOG_WELLNESS) {
        m->ip=3;
        m->useridentifier = -1;
        m->userid = -1;
        m->timestamp = 0;
        m->dif = -1;
        m->method = 5;
        m->uri = 6;
        m->protocol = 7;
        m->status_code = -1;
        m->return_size = -1;
        m->referer = -1;
        m->user_agent = -1;
		m->nfields = 10;
    } else if (log_type == LOG_LIST) {
        m->ip=-1;
        m->useridentifier = -1;
        m->userid = -1;
        m->timestamp = -1;
        m->dif = -1;
        m->method = -1;
        m->uri = 0;
        m->protocol = -1;
        m->status_code = 1;
        m->return_size = -1;
        m->referer = -1;
        m->user_agent = -1;
		m->nfields = 1;
    } else if (log_type == LOG_URI) {
        m->ip=-1;
        m->useridentifier = -1;
        m->userid = -1;
        m->timestamp = -1;
        m->dif = -1;
        m->method = -1;
        m->uri = 1;
        m->protocol = -1;
        m->status_code = 2;
        m->return_size = -1;
        m->referer = -1;
        m->user_agent = -1;
		m->nfields = 2;
    } else if (log_type == LOG_ELIST) {
        m->ip=-1;
        m->useridentifier = -1;
        m->userid = -1;
        m->timestamp = -1;
        m->dif = -1;
        m->method = 1;
        m->uri = 2;
        m->protocol = 3;
        m->status_code = 4;
        m->return_size = 5;
        m->referer = -1;
        m->user_agent = -1;
		m->nfields = 5;
	}

	if (uri_labels) { // Renumber all the mappings to include labels
		m->label = 0;
		m->ip ++;
        m->useridentifier ++;
        m->userid ++;
        m->timestamp ++;
        m->dif ++;
        m->method ++;
        m->uri ++;
        m->protocol ++;
        m->status_code ++;
        m->return_size ++;
        m->referer ++;
        m->user_agent++;
		m->nfields ++;
	} else m->label=-1;

    return;
}

/* Extraction of field values from a log line  */

int parse_apache_logEntry(char * logLine, Apache_logEntry * logEntry, log_map map, int logLinelen){

#define APACHE_LOG_TOKENS 12 //Maximum number of tokens on Apache entries

    //Temp strings in tokenizer process
    char * tmp_str[APACHE_LOG_TOKENS+1], tmp[WORDLENGTH];
    char * p;
    int pos,n, offset, nf, urilength = 0;

    //Tokenizer by white-space
    tmp_str[0] = strtok((char *)logLine, " ");
	nf = (uri_labels) ? APACHE_LOG_TOKENS +1 : APACHE_LOG_TOKENS;
    for (n=1; n < nf && tmp_str[n-1]!=NULL; n++){
        tmp_str[n] = strtok(NULL, " ");
		if (n == (map.uri+1)) urilength = tmp_str[n]-tmp_str[n-1];
#ifdef DEBUG2
        printf("\t[%s]",tmp_str[n]);
#endif
    }
#ifdef DEBUG2
        printf("\n[%d fields]",n );
#endif
	if (uri_labels) {
		if (tmp_str[0][0] == '[') {
			strcpy(logEntry->label,&(tmp_str[0][0]));
			p = strchr(logEntry->label,']');
			if (p) *(p+1) = '\0';
			else {
				printf("[parse_apache_logEntry]: ERROR - Bad formatted label [%s]`END line [%d] - Probably the type of log is incorrect \n",logEntry->label,nlineas);
				exit(-1);
			};
		} else {
				printf("[parse_apache_logEntry]: ERROR - Bad formatted label [%s], line [%d] - Probably the type of log is incorrect \n",tmp_str[0],nlineas);
				exit(-1);			
		};
	};

    /* Basic check of log type, n contains the number of fields plus 1 */

    if (((log_type == LOG_APACHE) && (n<10)) || ((log_type == LOG_WELLNESS) && (n < 11)) ) {
        if (nlineas == 1) {
            printf("[parse_apache_logEntry]: ERROR - Incorrect number of fields [%d], line [%d] - Probably the type of log is incorrect \n",n,nlineas);
            exit(-1);
        } else  {
            printf("[parse_apache_logEntry]: Parse error - line [%d] [",nlineas);
            for (pos=0;pos<n-2;pos++) printf("%s ",tmp_str[pos]);
            printf("%s]\n",tmp_str[n-2]);
            return(-1);
        }
    }

    offset = 0;

    /* Field processing */

    if (map.ip >= 0) {
        if (log_type == LOG_WELLNESS) {         /* Separation IP:port - IPv4 assumed */

            p = strstr(tmp_str[map.ip],":");
            if (p) *p = '\0';

        };
        if (strlen(tmp_str[map.ip]) > 40) {
            printf("[parse_logEntry]: IP field with erroneous format [%s], line [%d]\n",tmp_str[map.ip],nlineas);
            return(-1);
        }

        /* convert_ip(tmp_str[map.ip], logEntry->ip_address); */

		strcmp(logEntry->ip_address, tmp_str[map.ip]);

    }

    if (map.useridentifier >= 0)
        if (tmp_str[map.useridentifier])
            strcpy(logEntry->user_identifier,tmp_str[map.useridentifier]);

    if (map.userid >0)
        if (tmp_str[map.userid])
            strcpy(logEntry->user_id, tmp_str[map.userid]);

    if (map.timestamp >= 0)
        if(tmp_str[map.timestamp]) {
            if (log_type == LOG_APACHE) {
                strcpy(tmp, tmp_str[map.timestamp]);
                strcat(tmp, tmp_str[map.dif]);
                strptime(tmp, "[%d/%b/%Y:%T%z]", &logEntry->time);
            } else if (map.timestamp >0) strptime(tmp_str[map.timestamp], "[%d/%b/%Y:%T%z]", &logEntry->time);
        }

    /* Valid methods */

    if (map.method >= 0) {
        if (!tmp_str[map.method]) {
           printf("[parse_apache_logEntry]: Method not found - Line [%d] \n",nlineas);
            return(-1);
        }

        if( strstr(tmp_str[map.method], "GET") != NULL )
            logEntry->request_method = GET;
        else if(strstr(tmp_str[map.method], "HEAD") != NULL )
            logEntry->request_method = HEAD;
        else if(strstr(tmp_str[map.method],"POST") != NULL)
            logEntry->request_method = POST;
        else if (strstr(tmp_str[map.method],"PROPFIND") != NULL)
            logEntry->request_method = PROPFIND;
        else if (strstr(tmp_str[map.method],"PUT") != NULL)
            logEntry->request_method = PUT;		else
			return(-1);
    }

    /* URI: This is the only mandatory field */

    pos = 0;
    if (!tmp_str[map.uri]) {
           printf("[parse_apache_logEntry]: URI not found, line [%d]\n",nlineas);
           return(-1);
    }
    while (tmp_str[map.uri][pos] == '"') { pos++; urilength--;	};				// Eliminate initial "
    if (!strncmp(&tmp_str[map.uri][pos],"http://",7) ) { pos += 7; urilength -= 7;}     // Elimnate http:// to avoid conflicts with rules with :
    memcpy(logEntry->URI, &tmp_str[map.uri][pos], sizeof(char)*(urilength+1));
	logEntry->URI[urilength] = '\0';

    pos = urilength;
    if (logEntry->URI[pos-1] == '"') { pos--; urilength--; };							// Eliminate ending "
    while (logEntry->URI[pos-1] == '\n') { pos--; urilength--; }
    logEntry->URI[pos] = '\0';
	logEntry->urilen = urilength;

    /* Protocol */

    if (map.protocol > 0)
        if (tmp_str[map.protocol])
            if( strstr(tmp_str[map.protocol], "HTTP/1.0") != NULL )
                logEntry->Protocol = _1_0;
            else if( strstr(tmp_str[map.protocol], "HTTP/1.1") != NULL )
                logEntry->Protocol = _1_1;
            else {
                logEntry->Protocol = _VOID;
                offset = -1;
#ifdef DEBUG
                printf("[parse_apache_logEntry]: Protocol field not found\n");
#endif
            };

    if (map.status_code >= 0) if (tmp_str[map.status_code + offset]) logEntry->status_code = atoi(tmp_str[map.status_code + offset]);

    if (map.return_size >= 0) if (tmp_str[map.return_size + offset]) logEntry->return_size = atoi(tmp_str[map.return_size + offset]);

#ifdef DEBUG
    printf("[parse_apache_logEntry]: status [%d] size [%d]\n", logEntry->status_code, logEntry->return_size);
#endif

    // Optional fields in the log

    if (map.referer >= 0)
        if(tmp_str[map.referer + offset])
            if(tmp_str[map.referer + offset][1] == '-')
                logEntry->referer[0] = '\0';
            else
                strcpy(logEntry->referer, tmp_str[map.referer + offset]);

    if (map.user_agent >= 0) if(tmp_str[map.referer + offset])  strcpy(logEntry->user_agent, &tmp_str[map.user_agent + offset][1]);

    return(0);
 #ifdef DEBUG
    printf("[parse_apache_logEntry]: URI [%s]\n",logEntry->URI);
#endif
}

/* Parse other formats (not apache alike) */

/* LIST format (optional labels)*/

int parse_list_logEntry(char * logLine, Apache_logEntry * logEntry, log_map map, int logLinelen) {

    char * p;
    int len;

	// Label

	if (uri_labels) {
		p = strchr(logLine,']');
		if (p != NULL) {
			len = p - logLine +1;
			strncpy(logEntry->label,logLine, len);
			logEntry->label[len] = '\0';
			p++;
			while ((*p == '\t') || (*p == ' ')) p++;
		} else {
			printf("[parse_list_logEntry]: Error reading label in line [%d] \n",nlineas);
			return(-1);
		};
	} else {
		p = logLine;
		if (*p == '[') {
			printf("[parse_list_logEntry]: Error - Possible label identified in line [%d] \n",nlineas);
			return(-1);
		};	
		logEntry->label[0] = '\0';
	}

	// URI
	// Remove initial http:// an https:// if present
	if (!strncmp(p,"http://",7) ) p += 6;   // Eliminate http[s]:// to avoid conflicts with rules with :
	if (!strncmp(p,"https://",8) ) p += 7;

	len = logLinelen - (p - logLine)-1;
	if (len > URILENGTH) {
        printf("[parse_list_logEntry]: Parse error - line too long [%d] [",nlineas);
		return(-1);
	}
	memcpy(logEntry->URI,p,sizeof(char)*len);
	logEntry->URI[len] = '\0';

	// Cleaning up the end of the uri (it should be a \n\0 sequence)

	if ((logEntry->URI[len-1] == '\n')) {
		logEntry->URI[len-1] = '\0';
		len -= 1;
	}
	logEntry->urilen = len;

#ifdef DEBUG2
    printf("[parse_list_logEntry]: URI [%s] length [%d] medida [%d]\n",logEntry->URI,len, strlen(logEntry->URI));
#endif

 #ifdef DEBUG
    printf("[parse_list_logEntry]: URI [%s]\n",logEntry->URI);
#endif
    return(0);
}

/* ELIST format (optional labels)*/
/* METHOD URI PROT" RES_CODE RES_LEN */

int parse_elist_logEntry(char * logLine, Apache_logEntry * logEntry, log_map map, int logLinelen){

    char * p, *q, *u;
	char tmp[URILENGTH];
    int len, error;

	// Label

	if (uri_labels) {
		p = strchr(logLine,']');
		if (p != NULL) {
			len = p - logLine +1;
			strncpy(logEntry->label,logLine, len);
			logEntry->label[len] = '\0';
			p++;
			while ((*p == '\t') || (*p == ' ')) p++;
		} else {
			printf("[parse_elist_logEntry]: Error reading label in line [%d] \n",nlineas);
			return(-1);
		};
	} else {
		p = logLine;
		if (*p == '[') {
			printf("[parse_elist_logEntry]: Error - Possible label identified in line [%d] \n",nlineas);
			return(-1);
		};	
		logEntry->label[0] = '\0';
	}

	// METHOD

	q = strchr(p,' ');
	strncpy(tmp,p,q-p);
	tmp[q-p] = '\0';

	if( strstr(tmp, "GET") != NULL )
		logEntry->request_method = GET;
	else if(strstr(tmp, "HEAD") != NULL )
		logEntry->request_method = HEAD;
	else if(strstr(tmp,"POST") != NULL)
		logEntry->request_method = POST;
	else if (strstr(tmp,"PROPFIND") != NULL)
		logEntry->request_method = PROPFIND;
    else if (strstr(tmp,"PUT") != NULL)
        logEntry->request_method = PUT;
	else {
        printf("[parse_elist_logEntry]: Invalid method [%s] found in line [%d]\n",tmp, nlineas);
		return(-1);
	}
	// Remove initial http[s]:// from uri if present
	q++;
	if (!strncmp(q,"http://",7) ) q += 6;   // Elimnate http:// to avoid conflicts with rules with :
	if (!strncmp(q,"https://",8) ) q += 7;   
	u = q;

	// Resp_len (ignored)

	p = logLine + logLinelen;
	while ((* p != ' ') && (p > logLine)) p--;
	error = sscanf(p,"%d",&logEntry->return_size);
	if ((error != 1) && ( p[1] != '-')) {
        printf("[parse_elist_logEntry]: Error reading response size [%s] in line [%d] \n",p,nlineas);
		return(-1);
	}

	// Response code

	p--;
	while ((* p != ' ') && (p > logLine)) p--;
	error = sscanf(p,"%d",&logEntry->status_code);
	if ((error != 1) ) {
        printf("[parse_elist_logEntry]: Error reading response code [%s] in line [%d] \n",p,nlineas);
		return(-1);
	}

	// URI (including protocol
	p--;
	if (*p != '"') {
        printf("[parse_elist_logEntry]: Error in final uri delimiter in line [%d] \n",nlineas);
		return(-1);
	}
	p--;
	strncpy(tmp,p-8,8);

	// Protocol (if it exists)

	if( strstr(tmp, "HTTP/1.0") != NULL )
        logEntry->Protocol = _1_0;
    else if( strstr(tmp, "HTTP/1.1") != NULL )
        logEntry->Protocol = _1_1;
	else {
        logEntry->Protocol = _VOID;
        p -=9;
    }

	// u points to the begining of the URI and p to the end

	len = p-u +1;
	if (len > URILENGTH) {
        printf("[parse_list_logEntry]: Parse error - line too long [%d] [",nlineas);
		return(-1);
	}
	memcpy(logEntry->URI,u,sizeof(char)*len);
	logEntry->URI[len] = '\0';

	// Cleaning up the end of the uri (it should be a \n\0 sequence)

	if ((logEntry->URI[len-1] == '\n')) {
		logEntry->URI[len-1] = '\0';
		len -= 1;
	}
	logEntry->urilen = len-1;

    return(0);
#ifdef DEBUG
    printf("[parse_list_logEntry]: URI [%s]\n",logEntry->URI);
#endif

}

/* URI format (optional labels)*/

int parse_uri_logEntry(char * logLine, Apache_logEntry * logEntry, log_map map, int logLinelen){

    char * p, *q;
    int len, error;

	// Label

	if (uri_labels) {
		p = strchr(logLine,']');
		if (p != NULL) {
			len = p - logLine +1;
			strncpy(logEntry->label,logLine, len);
			logEntry->label[len] = '\0';
			p++;
			while ((*p == '\t') || (*p == ' ')) p++;
		} else {
			printf("[parse_uri_logEntry]: Error reading label in line [%d] \n",nlineas);
			return(-1);
		};
	} else {
		p = logLine;
		if (*p == '[') {
			printf("[parse_uri_logEntry]: Error - Possible label identified in line [%d] \n",nlineas);
			return(-1);
		};	
		logEntry->label[0] = '\0';
	}

	// Length of the uri

	q = strchr(p,' ');
	if (q == NULL) {
		printf("[parse_uri_logEntry]: Error reading size in line [%d] \n",p,nlineas);
		return(-1);
	};
	error = sscanf(p,"%d",&len);
	if (error != 1) {
        printf("[parse_uri_logEntry]: Error reading uri size [%s] in line [%d] \n",p,nlineas);
		return(-1);
	}
	q++;

	// URI
	// Remove initial http:// if present
	if (!strncmp(q,"http://",7) ) q += 6;   // Elimnate http:// to avoid conflicts with rules with :
	if (!strncmp(q,"https://",8) ) q += 7;   

	if (len > URILENGTH) {
        printf("[parse_uri_logEntry]: Parse error - line too long [%d]\n",nlineas);
		return(-1);
	}
	memcpy(logEntry->URI,q,sizeof(char)*len);
	logEntry->URI[len] = '\0';

	// Cleaning up the end of the uri (it should be a \n\0 sequence)

	if ( (logEntry->URI[len-1] == '\n')) {
		logEntry->URI[len-1] == '\0';
		len -= 1;
	}
	logEntry->urilen = len;

    return(0);
 #ifdef DEBUG
    printf("[parse_uri_logEntry]: URI [%s]\n",logEntry->URI);
#endif

}

/* Empty log record */

void init_Apache_logEntry(Apache_logEntry * logEntry){

    logEntry->ip_address[0] = '\0';
    logEntry->user_identifier[0] = '\0';
    logEntry->user_id[0] = '\0';
    logEntry->request_method = NONE;
    logEntry->URI[0] = '\0';
    logEntry->Protocol = 0;
    logEntry->status_code = 0;
    logEntry->return_size = 0;

    /* --- Additional fields for Combined Log Format ---*/
    logEntry->referer[0] = '\0';
    logEntry->user_agent[0] = '\0';
	logEntry->label[0] = '\0';

}

int compare( const void* a, const void* b)
{
    unsigned int int_a = * ( (unsigned int*) a );
    unsigned int int_b = * ( (unsigned int*) b );

     if ( int_a == int_b ) return 0;
     else if ( int_a < int_b ) return -1;
     else return 1;
}

