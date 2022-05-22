/*
** INSPECTORLOG
** Todos los derechos reservados
** All rights reserved
**
** Copyright (C) 2017, Jesús E. Díaz Verdejo
** Versión 3.4 JEDV - 25/11/2021
** Versión 3.0 JEDV - 19/12/2017
**
** CHANGES:
**
**  v3.4: Added support for $URL rules
*/

//some extra functions that are defined in the X/Open and POSIX standards.
// #define _XOPEN_SOURCE 700
#define _XOPEN_SOURCE 700

//INSPECTORLOG INCLUDES
#include "inspector.h"

#undef DEBUG

// Port numbers considered as valid HTTP ports 

const char *http_ports[]={"$HTTP_PORTS","80","8080","8081","81","311","383","591","593","901","1220","1414","1741","1830","2301","2381","2809","3037","3128","3702","4343","4848","5250","6988","7000","7001","7144","7145","7510","7777","7779","8000","8008","8014","8028","8080","8085","8088","8090","8118","8123","8180","8181","8243","8280","8300","8800","8888","8899","9000","9060","9080","9090","9091","9443","9999","11371","34443","34444","41080","50002","55555"};

// const char *nem_types[]={"RL", "RLx", "WL", "WLx"};
// const char *nem_zone[]={"BODY","URL","ARGS","HEADERS","User-agent"};

#define nhttp_ports (sizeof(http_ports) / sizeof(const char *))

/****************************/
/* Auxiliary routines       */
/****************************/

// Removes all spaces from a (non-const) string.
void delete_whiteSpaces(char *str){

    char *src = str;
    char *dst = src;

    while (*src != '\0') {

        // If it's not a space, transfer and increment destination.
        if (*src != ' ')
            *dst++ = *src;

        // Increment source no matter what.

        src++;
    }
    *dst = '\0';
}

unsigned char char_toHex(char s){

    // ASCII coding is assumed 
    unsigned char hex = 1;

    if (s>='0' && s<='9'){
        hex = s - '0';
    } else if (s>='A' && s<='F'){
        hex = s -'A' + 10;
    } else if (s>='a' && s<='f'){
        hex = s -'a' + 10;
    } else{
        printf("[char_toHex]: ERROR - Error in 'char_toHex' : The input is not an hex value \n\n");
    }

    return hex;
}

/* Empty rule creation */

URI_rule * init_rule() {

    URI_rule * rule = (URI_rule*) uchar_malloc(sizeof(URI_rule));
    int i;
	
    rule->num_patt = 0;
    rule->num_pcre = 0;
    rule->urilen = 0;
    rule->uritype = 0;
	rule->WLr = false;
	rule->url_rule = false;
	rule->var_rule = false;
	rule->durl_rule = false;
    rule->num_ref = 0;
	for (i=0; i < MAX_REFERENCES; i++) rule->references[i] = NULL;
    rule->attack_type = NULL;	
    rule->description = NULL;	
	int score = -1;
    rule->sid = 0;  
	rule->engineid = 0;

    for(i=0; i < MAX_PATTERNS; i++){
        rule->URI_pattern[i].negated = 0;
        rule->URI_pattern[i].nocase = false;
		rule->URI_pattern[i].pattern_str = NULL;
    }

    for(i=0; i < MAX_PCRE; i++) {
        rule->pcre[i].negated = 0;
        rule->pcre[i].modifier = NULL;
        rule->pcre[i].regExp = NULL;
		rule->pcre[i].pattern = NULL;
    }

    return rule;
}

// Converts bytecodes in a content or pcre field to char 

void convert_bytecode(char * bytecode){

    delete_whiteSpaces(bytecode); // White spaces removal

    char * ptr = bytecode;

    unsigned char byte;
	int length = 0, j = 0, i=0;

    length = strlen(bytecode);
    if ( length <= 0) {
        printf("[convert_bytecode] Error - Input is an empty bytecode \n");
    } else if ( (length % 2) != 0 ) {
        printf("[convert_bytecode] Error - Input is an odd bytecode \n");
    } else {
        j=0;
        for(i=0; i < length; i=i+2, j++){

            unsigned char byte1 = char_toHex(ptr[i]);
            unsigned char byte2 = char_toHex(ptr[i+1]);

            byte = byte1*16 + byte2;

            bytecode[j] = byte;
        }
        bytecode[j] = '\0';
    }
}

// Regular expressions preprocessing to be stored in a rule 
// Assumed format '/expression/modifiers'

void parse_snortPcre(unsigned char * pcre, URI_rule * rule){

    char * msg_i = strchr (pcre, '/');
    if ( msg_i != NULL ){
        msg_i++;
        char * msg_e = strrchr (pcre, '/');
        if ( msg_e != NULL ){
            size_t length = msg_e - msg_i;
            rule->pcre[rule->num_pcre].regExp = uchar_malloc(length+1);
            strncpy(rule->pcre[rule->num_pcre].regExp, msg_i, length);
            rule->pcre[rule->num_pcre].regExp[length] = '\0';

            msg_e++;
            size_t length2 = strlen(msg_e);
            rule->pcre[rule->num_pcre].modifier = uchar_malloc(length2+1);
            strncpy(rule->pcre[rule->num_pcre].modifier, msg_e,length2); //Copy the post-re modifiers
			rule->pcre[rule->num_pcre].modifier[length2]='\0';
        }
    }
    return;
}

// Content field preprocessing to be stored in a rule 
// Finds and decode bytecoded chars

void parse_snortContent(char * content){

    unsigned char hexCodes_str[CONTENT_LENGTH];

    char tmp[CONTENT_LENGTH];
    tmp[0]='\0';

    char *aux = content;
    int i;
    for (i=0; i < MAX_BYTECODES; i++) { //Limited by the maximum number of different bytecodes in the same 'content'

        char * msg_i = strstr(aux, "|"); //The init of the "msg" field
        if ( msg_i != NULL ) {
            msg_i += strlen("|");
            char * msg_e = strstr(msg_i, "|"); //The end of the "msg" field
            if ( msg_e != NULL ) {
                size_t length2 = msg_i-aux-1;
                strncat(tmp, aux, length2);
                size_t length = msg_e - msg_i;
                strncpy(hexCodes_str, msg_i, length);
                hexCodes_str[length] = '\0';
                aux = msg_e+1;
                convert_bytecode(hexCodes_str); //|0D 0A 0D 0A| ->\r\n\r\n
                strcat(tmp, hexCodes_str);
            }
        } else {
            strcat(tmp, aux); // Remaining content string is copied 
			break;
        }
    }
    
    if (i > 0) // Whether any bytecode was present in 'content' 
        strcpy(content, tmp);
}

// NEMESIDA rule (text) parsing - It is added to rule list
// Rule format: (tab separated)
// 31	RLx	(\d+\s*,\s*){4,}	SQLi	4	BODY|URL|ARGS|HEADERS

bool parse_nemesidaRule(const char * origRule){

    bool isRuleOK = true; 			// Rule parsing is correct
    char hdr_str[NEMESIDA_HEADER_TOKENS][SNORT_RULE_MAX];	//Temp pointer strings in tokenizer header process
	char *p, *q;;
	
	int options;					// PCRE options
	bool pcre_rule = false;
    int error_id;
    int error_offset;
    char *error;   
	
	int n;

    //To avoid modification of "origRule"

	n = strlen(origRule);
    if (n > SNORT_RULE_MAX) {
        printf("[nemesida_rule]: ERROR - Rule longer than SNORT_RULE_MAX [%d]\n",SNORT_RULE_MAX);
        num_errorrules[NEMESIDA] ++;
		num_errorrules[0]++;
        return(false);
    } 
	num_rules_file++;
	
	// Comment line
	
	if (origRule[0] == '#') return(false);
	
	num_rules[NEMESIDA]++;
	num_rules[0]++;
	
#ifdef DEBUG
    printf(">>>> Parsing line [%d]: Rule [%s]\n",num_rules_file,origRule);
#endif

    //Tokenizer by tabs

	p = origRule;
	for(n=1; n < NEMESIDA_HEADER_TOKENS; n++) {
		q = strchr(p,'\t');
		if (q == NULL) {
			num_errorrules[NEMESIDA] ++;
			num_errorrules[0]++;
			printf("[nemesida_rule]: Incorrect header in line [%d],  [%d] fields\n",num_rules_file,n);
			isRuleOK = false;	
			return(false);
		};
		strncpy(hdr_str[n-1],p,q-p);
		hdr_str[n-1][q-p] = '\0';
		p = q+1;
	};
	strcpy(hdr_str[n-1],p);


#ifdef DEBUG
	printf("\nVALORES [%d]\n",n);
	for (n=0; n < NEMESIDA_HEADER_TOKENS; n++) {
		printf("%d [%s] \t",n,hdr_str[n]);
	};
	printf("\n");
#endif	

	// Check wheter URL or ARGS is affected, otherwise rule is dismissed
	
	if ((strstr(hdr_str[NEM_FIELD-1],"URL") != NULL) || (strstr(hdr_str[NEM_FIELD-1],"ARGS") != NULL)) {
		isRuleOK = true;
	} else {
		isRuleOK = false;
	};
	
	
    if (isRuleOK ) { 		// Parse the rule

		size_t length;
        
        URI_rule * rule = init_rule();      /* Create a new empty rule */

        /* Field proccessing - ordered */
		/* SID */
       
		error_id = sscanf(hdr_str[NEM_SID-1],"%d",&rule->sid);
		if (error_id != 1) {
			printf("[nemesida_rule]: ERROR - Incorrect SID decoding in rule [%d] fields\n",num_rules_file);
			free_rule(rule);
			return(false);
		}
		rule->sid += NEMESIDA_OFFSET;
		rule->engineid = NEMESIDA;

#ifdef DEBUG
        printf("\n\t\t\tExtracted sid: [%d]\n",rule->sid);
#endif
        /* Rule type 
		/* Options RL, WL, RLx, WLx */

		if (!strcmp(hdr_str[NEM_TYPE-1],"RL")) {
			rule->WLr = false;
			pcre_rule = false;
		} else if (!strcmp(hdr_str[NEM_TYPE-1],"RLx")) {
			rule->WLr = false;
			pcre_rule = true;
		} else if (!strcmp(hdr_str[NEM_TYPE-1],"WL")) {
			rule->WLr = true;
			pcre_rule = false;
		} else if (!strcmp(hdr_str[NEM_TYPE-1],"WLx")) {
			rule->WLr = true;
			pcre_rule = true;
		} else {
			printf("[nemesida_rule]: ERROR - Incorrect TYPE decoding in rule [%d]: SID[%d] type [%s]\n",num_rules_file,rule->sid,hdr_str[NEM_TYPE-1]);
			free_rule(rule);
			return(false);			
		}
#ifdef DEBUG
        printf("\n\t\t\tExtracted type: white [%d] pcre [%d]\n",rule->WLr, pcre_rule);
#endif
        /* Rule content */

		if (!pcre_rule) {			// Normal content rule
		
			// Patch to handle nemesida rule 2712 with coded space 
			if (strstr(hdr_str[NEM_CONTENT-1],"%20")) decodespaces_uri(hdr_str[NEM_CONTENT-1]);

			length = strlen(hdr_str[NEM_CONTENT-1]);
			
			if (length > 0) {
				
				rule->URI_pattern[rule->num_patt].pattern_str = uchar_malloc(length+1);
				strncpy(rule->URI_pattern[rule->num_patt].pattern_str, hdr_str[NEM_CONTENT-1],length);
				rule->URI_pattern[rule->num_patt].pattern_str[length] = '\0';

				rule->URI_pattern[rule->num_patt].nocase = false;
				rule->URI_pattern[rule->num_patt].negated = false;
#ifdef DEBUG
				printf("\t\t\tExtracted content: [%s]\n",rule->URI_pattern[rule->num_patt].pattern_str);
#endif
				rule->num_patt++;

			} else {
				printf("[nemesida_rule]: WARNING - Error parsing content in rule [%d]\n",num_rules_file);
			}   
		} else {				// Regular expression rule

			if (strstr(hdr_str[NEM_CONTENT-1],"%20")) decodespaces_uri(hdr_str[NEM_CONTENT-1]);

			length = strlen(hdr_str[NEM_CONTENT-1]);          
                
			if (length > 0) {

				rule->pcre[rule->num_pcre].negated = false;;
				
				/* For nemesida rules, regular expression is as is, no need to call parse_snortPcre */

				rule->pcre[rule->num_pcre].regExp = uchar_malloc(length+1);
				strncpy(rule->pcre[rule->num_pcre].regExp, hdr_str[NEM_CONTENT-1], length);
				rule->pcre[rule->num_pcre].regExp[length] = '\0';
				
				/* PCRE compilation */
				
				if (nocase) options = PCRE_CASELESS || PCRE_DOTALL;
				else options = PCRE_DOTALL;
				
				rule->pcre[rule->num_pcre].pattern = pcre_compile2(rule->pcre[rule->num_pcre].regExp, options, &error_id, &error, &error_offset, NULL);

				if (!rule->pcre[rule->num_pcre].pattern) {
					printf("[nemesida_rule]: ERROR - pcre_compile failed (offset: %d) error %s in rule [%d]\n", error_offset, error,num_rules_file);
					free_rule(rule);
					return(false);

				};
	#ifdef DEBUG
				printf("\tExtracted pcre: [%s]\n",rule->pcre[rule->num_pcre].regExp);
	#endif
				rule->num_pcre++;
			}   
		}
		
		/* Attack class */

		length = strlen(hdr_str[NEM_ATTACK_TYPE-1]);
		
        if (length > 0) {
			rule->description = uchar_malloc(length+1);
			strncpy(rule->description, hdr_str[NEM_ATTACK_TYPE-1], length);
			rule->description[length] = '\0';
			rule->attack_type = uchar_malloc(length+1);
			strncpy(rule->attack_type, hdr_str[NEM_ATTACK_TYPE-1], length);
			rule->attack_type[length] = '\0';   
#ifdef DEBUG
			printf("\tExtracted description: [%s]\n",rule->description);
#endif
		}

		/* Score / priority */
		
		length = strlen(hdr_str[NEM_SCORE-1]);

        if (length > 0) {
			
			error_id = sscanf(hdr_str[NEM_SCORE-1],"%d", &(rule->score));

			if (error_id != 1) {
				printf("[nemesida_rule]: ERROR - Incorrect SCORE decoding in rule [%d]\n",num_rules_file);
				free_rule(rule);
				return(false);
			}			
			
#ifdef DEBUG
			printf("\tSeverity extracted: [%d]\n",rule->score);
#endif
		}
		
		/* Affected fields */
		/* $RULE is treated first */
		
		if (strstr(hdr_str[NEM_FIELD-1],"$URL") != NULL) {
			
			// $URL rule -> Check if it affects path or query
						
			if (!(strstr(hdr_str[NEM_FIELD-1],"BODY") && !strstr(hdr_str[NEM_FIELD-1],"ARGS") )) { // Rule must be processed
			
				rule->durl_rule = true;
				
				p = strchr(hdr_str[NEM_FIELD-1],':');
				if (p == NULL) {
					printf("[nemesida_rule]: ERROR - Incorrect $URL decoding in rule [%d]\n",num_rules_file);
					free_rule(rule);
					return(false);
				};
				p++;
				q = p;

				while ( (*q != '|') && (*q != '\n') && (*q != '\0') ) {  q++;}
				
				// $URL pattern will be placed at special pattern DURL

				rule->DURL = uchar_malloc(q-p+1);
				strncpy(rule->DURL,p,q-p);
				rule->DURL[q-p] = '\0';
				
				if (strstr(hdr_str[NEM_FIELD-1],"ARGS") != NULL) rule->var_rule = true;
				
			};
		} else {
			if (strstr(hdr_str[NEM_FIELD-1],"URL") != NULL) rule->url_rule = true;
			if (strstr(hdr_str[NEM_FIELD-1],"ARGS") != NULL) rule->var_rule = true;
		};

#ifdef DEBUG
			printf("\tAffected fields: [%d] [%d]\n",rule->url_rule,rule->var_rule);
#endif		
        /* Rule processing is finished: checks */

		if ( (rule->sid > 0) && ((rule->num_patt > 0) || (rule->num_pcre > 0) )) {   /* Regla con campos mínimos */
			if (num_URIrules[0] < MAX_URI_RULES) {
				URI_rules[num_URIrules[0]] = rule;
				num_URIrules[NEMESIDA]++;
				num_URIrules[0] ++;
			
			} else {
				printf("[nemesida_rule] : ERROR - Exceeded maximum number of rules = %i\n", MAX_URI_RULES);
				free_rule(rule);
				isRuleOK = false;
			}
		} else {
			printf("[nemesida_rule] : WARNING - Rule [%d] lacks mandatory fields\n", num_rules_file);
			free_rule(rule);
			isRuleOK = false;
		};
    }

    return isRuleOK;
}


// Snort rule (text) parsing - It is added to rule list
/* ----------------- PARSE HEADER ----------------- */

bool parse_snortRule(const char * origRule){

    bool isRuleOK = true; 		// Rule parsing is correct
    bool is_HTTP_rule = false; 	// URI related rule, should be considered
    bool cwarning = false, rwarning = false;    // Excesive number of fields warnings
    char rule_str[SNORT_RULE_MAX], opt_str[SNORT_RULE_MAX], content[SNORT_RULE_MAX];
	int options;				// PCRE options
    int error_id, error_offset;	// PCRE error codes
    const char *error;			// PCRE error message
	int j;						// Auxiliary
	
    //To avoid modification of "origRule"

    if (strlen(origRule) > SNORT_RULE_MAX) {
        printf("[snort_rule]: ERROR - Rule longer than SNORT_RULE_MAX [%d]\n",SNORT_RULE_MAX);
        num_errorrules[SNORT] ++;
		num_errorrules[0]++;
        return(false);
    } else {
        strncpy(rule_str, origRule, SNORT_RULE_MAX);       
    }

#ifdef DEBUG
    printf(">>>> Parsin line [%d]: Rule [%s]\n",num_rules_file,rule_str);
#endif
    /* CABECERA DE LA REGLA  */
    //Temp pointer strings in tokenizer header process
    
    char * hdr_str[SNORT_HEADER_TOKENS];

    //Tokenizer by white-space

    int n;
    hdr_str[0] = strtok((char *)rule_str, " ");
    for(n=1; hdr_str[n-1]!=NULL && n<SNORT_HEADER_TOKENS; n++){
        hdr_str[n] = strtok(NULL, " ");
    }

    if(n != SNORT_HEADER_TOKENS){
        num_errorrules[SNORT] ++;
        printf("[snort_rule]: Incorrect header in line [%d], only [%d] fields\n",num_rules_file,n);
        isRuleOK = false;
    } else {
        for (j=0; j < nhttp_ports; j++) {
            if (!strcmp(hdr_str[PDEST], http_ports[j])) {
                is_HTTP_rule = true;
                break;
            };
        }
    }

    /* ----------------- PARSE OPTIONS ----------------- */

    if (isRuleOK && is_HTTP_rule) { //Check if header is OK

        //Get the options string
        char *tmpfield = NULL, *tmpvalue = NULL;
        size_t length;

#ifdef DEBUG2
        printf("\t> La regla es HTTP -> descomponiendola\n");
#endif
        strncpy(rule_str, origRule, SNORT_RULE_MAX);
        tmpfield = strstr(rule_str,"(");            /* Puntero al inicio de las opciones */
        if (!tmpfield) {                              // Error en las opciones
            printf("[snort_rule]: Line [%d] Error processing options - Not found\n",num_rules_file);
            isRuleOK = false;
            num_errorrules[SNORT] ++;
            return(isRuleOK);
        };
        
        URI_rule * rule = init_rule();      /* Creamos una regla vacía */


       	strncpy(opt_str,tmpfield+1,SNORT_RULE_MAX);
#ifdef DEBUG2
        printf("\tOpciones: %s\n",opt_str);
#endif
        /* Vamos parseando las opciones una a una y clasificándolas */
       
        tmpfield = strtok(opt_str,";");

        /* Segmentamos los campos y vamos seleccionando los que nos interesan */
        
        while ((tmpfield) && strcmp(tmpfield,")")) {
#ifdef DEBUG
        	printf("\t\tSegmento [%s]\n",tmpfield);
#endif
        	while(tmpfield[0]==' ') tmpfield ++;    /* Limpiamos espacios en blanco al inicio */
            if (!strncmp(tmpfield,"msg:",4)) {     /* Mensaje */
            
                tmpvalue = tmpfield + strlen("msg:"); /* Evitamos las comillas iniciales */
                
                if (tmpvalue[0] == '\"') tmpvalue++; /* Evitamos las comillas inicial y final */
                length = strlen(tmpvalue);
                if (tmpvalue[length-1] == '\"') {
                    tmpvalue[length-1] = '\0';
                    length--;
                }
                if (length > 0) {
                    rule->description = uchar_malloc(length+1);
                    strncpy(rule->description, tmpvalue, length);
                    rule->description[length] = '\0';   
#ifdef DEBUG
                    printf("\t\t\tExtraida descripción: [%s]\n",rule->description);
#endif
                }

                
            } else if (!strncmp(tmpfield,"reference:",10)) {
                    
                if (rule->num_ref < MAX_REFERENCES) {
                    tmpvalue = tmpfield + strlen("reference:"); 
                    length = strlen(tmpvalue);
                    rule->references[rule->num_ref] = uchar_malloc(length+1);
                    strncpy(rule->references[rule->num_ref], tmpvalue, length);
                    rule->references[rule->num_ref][length] = '\0';
#ifdef DEBUG
                printf("\t\t\tExtraida reference: [%s]\n",rule->references[rule->num_ref]);
#endif
                    rule->num_ref++;
                } else if (!rwarning) {
                    printf("[parse_snortrule]: WARNING - Line [%d] exceeds allowed number of references \n",num_rules_file);
                    rwarning = true;
                }

            } else if (!strncmp(tmpfield,"classtype:",10)) {

                    tmpvalue = tmpfield + strlen("classtype:"); 
                    length = strlen(tmpvalue);
                    rule->attack_type = uchar_malloc(length+1);
                    strncpy(rule->attack_type, tmpvalue, length);
                    rule->attack_type[length] = '\0';
#ifdef DEBUG
                printf("\t\t\tExtraido attack_type: [%s]\n",rule->attack_type);
#endif
            } else if (!strncmp(tmpfield,"pcre:",5)) {

                if (rule->num_pcre >= MAX_PCRE) printf("[parse_snortRule] WARNING: Line [%d] exceeds allowed number of PCRE fields\n",num_rules_file);
                tmpvalue = tmpfield + strlen("pcre:");                
                if (tmpvalue[0] == '"') tmpvalue++; /* Avoid initial and final quotation marks  */
                length = strlen(tmpvalue);
                
                /* Particular case: ';' appears in a pcre or content field - More pieces should be added */
                
                if (tmpvalue[length-1] == '\"') {
                    tmpvalue[length-1] = '\0';
                    length--;
                    strncpy(content,tmpvalue,length);
                    content[length]='\0';
                } else {
                    /* Particular case: ';' appears in a pcre or content field - More pieces should be added */

                    strncpy(content,tmpvalue,length);
                    content[length]='\0';
                    strcat(content,";");
                    if (tmpvalue[length+1]!='"') {    /* There is a problem in case ';' is the last character in a content field */
                            tmpfield=strtok(NULL,"\";");
                            if (!tmpfield) {
                                printf("[parse_snortRule]: ERROR - Error en campo pcre regla [%d]\n", num_rules_file);
                                exit(-1);                      
                            }
                            strcat(content,tmpfield);
                            length += strlen(tmpfield)+1; 
                    } else {
                            length +=1;
                    }       
                        
                }
                
                if (length > 0) {

                    if  ( content[0] == '!')   {  // It is a negated regular expression 
                        rule->pcre[rule->num_pcre].negated = true;
                        tmpvalue++;
                    } else {
                        rule->pcre[rule->num_pcre].negated = false;
                    }

                    /* WARNING: Nor bytecodes nor scaped nor especial charecters are handled in a pcre expression */
                    
                    parse_snortPcre(content, rule);		// Regular expression loading and processing 
					
					/* PCRE compilation  */
					
					if (nocase) options = PCRE_CASELESS || PCRE_DOTALL;
					else options = PCRE_DOTALL;
					
					if (strchr(rule->pcre[rule->num_pcre].modifier,'i')) options = options || PCRE_CASELESS;

					rule->pcre[rule->num_pcre].pattern = pcre_compile2(rule->pcre[rule->num_pcre].regExp, options, &error_id, &error, &error_offset, NULL);

					if (!rule->pcre[rule->num_pcre].pattern) printf("[parse_snortRule]: pcre_compile failed (offset: %d) error %s in line [%d]\n", error_offset, error,num_rules_file);

					// TODO: Handle error by '/' at the end of PCRE
#ifdef DEBUG
                    printf("\tPCRE extracted: [%s]\n",rule->pcre[rule->num_pcre].regExp);
#endif
                    rule->num_pcre++;

                }            
            } else if ((!strncmp(tmpfield,"content:",8)) || (!strncmp(tmpfield,"uricontent:",11))) {
                if (rule->num_patt < MAX_PATTERNS) {
                    if (!strncmp(tmpfield,"content:",8)) tmpvalue = tmpfield + strlen("content:");
                    else tmpvalue = tmpfield + strlen("uricontent:");                    
                    if (tmpvalue[0] == '"') tmpvalue++; /* Avoid initial and ending quotation marks  */
                    length = strlen(tmpvalue);
                    if (tmpvalue[length-1] == '\"') {
                        tmpvalue[length-1] = '\0';
                        length--;
                        strncpy(content,tmpvalue,length);
                        content[length]='\0';
                    } else { /*  Particular case: ';' appears in a pcre or content field - More pieces should be added */
                        strncpy(content,tmpvalue,length);
                        content[length]='\0';
                        strcat(content,";");
                        if (tmpvalue[length+1]!='"') {    /* There is a problem in case ';' is the last character in a content field */
                            tmpfield=strtok(NULL,"\";");
                            if (!tmpfield) {
                                printf("[parse_snortRule]: ERROR - Error in content field, line [%d]\n", num_rules_file);
                                exit(-1);                      
                            }
                            strcat(content,tmpfield);
                            length += strlen(tmpfield)+1; 
                        } else {
                            length +=1;
                        }                     
                    }                

                    if ((length > 0) && (length < CONTENT_LENGTH)) {
                        
                        rule->URI_pattern[rule->num_patt].pattern_str = uchar_malloc(length+1);
                        strncpy(rule->URI_pattern[rule->num_patt].pattern_str, content, length);
                        rule->URI_pattern[rule->num_patt].pattern_str[length] = '\0';

                        parse_snortContent(rule->URI_pattern[rule->num_patt].pattern_str);
                        rule->URI_pattern[rule->num_patt].nocase = false;
#ifdef DEBUG
                        printf("\t\t\tContent extracted: [%s]\n",rule->URI_pattern[rule->num_patt].pattern_str);
#endif
                        rule->num_patt++;

                    } else {
                        printf("[parse_snortrule]: WARNING - Error parsing content in line [%d]\n",num_rules_file);
                    }   
                } else if (!cwarning) {                  
                    printf("[parse_snortrule]: WARNING - Line [%d] exceeds maximun allowed number of content fields \n",num_rules_file);
                    cwarning = true;
                }               
            } else if (!strncmp(tmpfield,"urilen:",7)) {
                    tmpvalue = tmpfield + strlen("urilen:"); 
                    length = strlen(tmpvalue);
                    if (tmpvalue[0]=='>') {
                        tmpvalue++;
                        rule->uritype=URILENGT;
                    } else if (tmpvalue[0]=='<') {
                        tmpvalue++;
                        rule->uritype=URILENLT;
                    } else rule->uritype=URILENEQ;
                    sscanf(tmpvalue,"%d",&rule->urilen);
#ifdef DEBUG
                    printf("\t\t\turilen extracted: [%d]\n",rule->urilen);
#endif
            } else if (!strncmp(tmpfield,"dsize:",6)) {
                    tmpvalue = tmpfield + strlen("dsize:"); 
                    length = strlen(tmpvalue);
                    if (rule->urilen == 0) {
                        if (tmpvalue[0]=='>') {
                            tmpvalue++;
                            rule->uritype=URILENGT;
                        } else if (tmpvalue[0]=='<') {
                            tmpvalue++;
                            rule->uritype=URILENLT;
                        } else rule->uritype=URILENEQ;
                        sscanf(tmpvalue,"%d",&rule->urilen);
                    }
#ifdef DEBUG
                    printf("\t\t\tExtracted dsize as urilen: [%d]\n",rule->urilen);
#endif
            } else if (!strncmp(tmpfield,"nocase",6)) {
                if (rule->num_patt > 0) {
                    rule->URI_pattern[rule->num_patt-1].nocase = true;
#ifdef DEBUG
                    printf("\t\t\tExtracted nocase for content [%d]\n",rule->num_patt-1);
                } else {
                    printf("[parse_snortRule] WARNING: nocase found without previous content  - Line [%d]\n",num_rules_file);
#endif
				}
            } else if (!strncmp(tmpfield,"sid:",4)) {
                    tmpvalue = tmpfield + strlen("sid:"); 
                    length = strlen(tmpvalue);
                    sscanf(tmpvalue,"%d",&rule->sid);
					rule->sid += SNORTSID_OFFSET;
					rule->engineid = SNORT;
					rule->url_rule = true;
					rule->var_rule = true;
#ifdef DEBUG
                    printf("\t\t\tExtracted sid: [%d]\n",rule->sid);
#endif
            } else if (!strncmp(tmpfield,"http_method",11)) {
                    if ( (!strstr(rule->URI_pattern[rule->num_patt-1].pattern_str, "GET") || !strstr(rule->URI_pattern[rule->num_patt-1].pattern_str, "POST") || 
						!strstr(rule->URI_pattern[rule->num_patt-1].pattern_str, "HEAD") || !strstr(rule->URI_pattern[rule->num_patt-1].pattern_str, "PROPFIND") ) )  {
								rule->num_patt--;
								free(rule->URI_pattern[rule->num_patt].pattern_str);
								rule->URI_pattern[rule->num_patt].pattern_str = NULL;
								rule->URI_pattern[rule->num_patt].nocase = false;
								rule->URI_pattern[rule->num_patt].negated = false;
					} else {
						printf("[parse_snortRule] WARNING: method found without associated valid content - Line [%d] Method [%s] -> Dismissed \n",num_rules_file,rule->URI_pattern[rule->num_patt-1].pattern_str);	
						isRuleOK = false;
					};
#ifdef DEBUG
                    printf("\t\t\tContent associated to method in line [%d] dissmised\n",num_rules);
#endif
            }
            tmpfield = strtok(NULL, ";");       

        }
     
        /* Basic rule checks */
        
        if (isRuleOK) {
			if ( (rule->sid > 0) && ((rule->num_patt > 0) || (rule->num_pcre > 0) )) {   /* Minimal required fields */
				if (num_URIrules[0] < MAX_URI_RULES) {
					URI_rules[num_URIrules[0]] = rule;
					num_URIrules[SNORT]++;
					num_URIrules[0] ++;
				} else {
					printf("[parse_snortRule] : ERROR - Maximum number of rules reached  = %i\n", MAX_URI_RULES);
					free_rule(rule);
				}
			} else {
				printf("[parse_snortRule] : WARNING - Line [%d] without minimal mandatory files \n", num_rules_file);
				isRuleOK = false;
				free_rule(rule);
				
			};
		} else free_rule(rule);
		
    } else {
        isRuleOK = false;
    }

    return isRuleOK;
}

/* Rule file (SNORT) processing */

void process_ruleFile_snort(FILE * rulesFile){

    size_t lineLength = 0;
    char * line = NULL;
    ssize_t read;

    int loadedRules = 0; //The number of correct loaded rules FOR THIS FILE (Not total)
	int i;
	
	line  = (char*) malloc (sizeof(char)*SNORT_RULE_MAX);
	if (line == NULL) {
		printf("[process_ruleFile_snort]: ERROR - Memory allocation error\n");
		exit(EXIT_FAILURE);
	}
	lineLength = SNORT_RULE_MAX*sizeof(char);


    //Read each of the lines ot the rules file
    for (i=1; (read = getline(&line, &lineLength, rulesFile)) != -1; i++) {
        
        num_rules[SNORT]++;
		num_rules[0]++;
        num_rules_file++;
 
        //Look if first character is '#' (that line is a comment)
        if (line[0] != '#' && line[0] != '\n') {
            if (parse_snortRule(line))
                loadedRules++;
        } else num_rules_file++;      
    }

    free(line);
}

/* Rule file (NEMESIDA) processing */

void process_ruleFile_nemesida(FILE * rulesFile){

    size_t lineLength = 0;
    char * line = NULL;
    ssize_t read;

    int loadedRules = 0; //The number of correct loaded rules FOR THIS FILE (Not total)
	int i;

	line  = (char*) malloc (sizeof(char)*SNORT_RULE_MAX);
	if (line == NULL) {
		printf("[process_ruleFile_nemesida]: ERROR - Memory allocation error\n");
		exit(EXIT_FAILURE);
	};
	lineLength = SNORT_RULE_MAX*sizeof(char);
	
    //Read each of the lines ot the rules file
    for (i=1; (read = getline(&line, &lineLength, rulesFile)) != -1; i++) {
         
        //Look if first character is '#' (that line is a comment)
        if (line[0] != '#' && line[0] != '\n') {
            if (parse_nemesidaRule(line))
                loadedRules++;
        } else num_rules_file++;     
    }

    free(line);
}

/* Go across directory of rule files (SNORT) and load rule files  */

int fileTree_handler(const char *relPath, const struct stat *sbuf, int type, struct FTW *ftwb){

    //Show the main path in absolute path form
#ifdef DEBUG
	printf("%d",ftwb->base);
#endif
    if ( ftwb->level == 0) {
        char absPath[PATH_MAX]; //Maximum number of bytes in a pathname, including terminating null byte
        if (realpath(relPath, absPath) != NULL)
            printf("# Rules directory : \"%s\"\n", absPath);
        else
            printf("# Rules directory : \"%s\"\n", relPath);

    } else if (ftwb->level > 0) {

        //If type == FILE
#ifdef DEBUG
    	printf("#>>> Abriendo archivo [%s]\n",relPath);
#endif
        if (type == FTW_F) {
            printf("#\tOpening SNORT rule file %s... ", relPath);
            FILE * rulesFile = fopen(relPath, "r");
                if (rulesFile == NULL) {
				printf("[load_rules_snort} - ERROR opening file %s\n",relPath);
                } else {
                    printf("done\n");
                    int newrules = num_rules[SNORT];
                    int newurirules = num_URIrules[SNORT];
                    int newerrors = num_errorrules[SNORT];
                    num_rules_file = 0;
                    process_ruleFile_snort(rulesFile);
                    printf("#\t\tRules: read [%d], erroneous [%d], URI [%d]\n",num_rules[SNORT]-newrules,num_errorrules[SNORT]-newerrors,num_URIrules[SNORT]-newurirules);
                    fclose(rulesFile);
                }

        //If type == DIR
        } else if (type == FTW_D) {
            printf("#\tOpening subdir %s... done\n", relPath);
        }
    }

    return 0;
}

/****************************/
/* Public routines          */
/****************************/

/* Rules' memory clean up */

void free_rule(URI_rule * rule){
	int i;
	
    if (rule->num_pcre){
        for(int i=0; i < rule->num_pcre; i++) {
			if (rule->pcre[i].regExp)  free(rule->pcre[i].regExp);
			if (rule->pcre[i].pattern) free(rule->pcre[i].pattern);
			if (rule->pcre[i].modifier) free(rule->pcre[i].modifier);
		};
        rule->num_pcre = 0;
    }

    for (i=0; i<rule->num_patt; i++){
        if (rule->URI_pattern[i].pattern_str) free(rule->URI_pattern[i].pattern_str);
    }
    rule->num_patt = 0;

    if (rule->description){
        free(rule->description);
    }

    for (i=0; i<rule->num_ref; i++){
        if (rule->references[i]) free(rule->references[i]);
    }
    rule->num_ref = 0;

    if (rule->attack_type){
        if (rule->attack_type) free(rule->attack_type);
    }
	if (rule) free(rule);

    return;
}

/* Load all the rule files in the rules directory (SNORT) */

void load_rules_snort(char *r_path){

    printf("#----- Initializing Rules (SNORT) ---------------------\n");
    if( nftw(r_path, fileTree_handler, 10, 0) == -1){
        printf("[load_rules] - ERROR - Rules directory not found = %s\n", r_path);
    }

    printf("#----- Statistics (SNORT) ------------------------------\n");
    printf("# Read [%d] Snort rules, [%d] http-related, [%d] with errors\n", num_rules[SNORT], num_URIrules[SNORT], num_errorrules[SNORT]);
}

/* Rules file loading (NEMESIDA) */

void load_rules_nemesida(char *rules_txt){

    printf("#----- Initializing Rules (NEMESIDA)  ---------------------\n");

	/* Open and process rule file (txt) */
	
    FILE * rulesFile = fopen(rules_txt, "r");
    if (rulesFile == NULL) {
		printf("[load_rules_nemesida] ERROR opening file %s\n",rulesFile);
	} else {
		printf("#\tOpening NEMESIDA rule file %s...\n", rules_txt);
        int newrules = num_rules[NEMESIDA];
        int newurirules = num_URIrules[NEMESIDA];
        int newerrors = num_errorrules[NEMESIDA];
        num_rules_file = 0;
        process_ruleFile_nemesida(rulesFile);
        printf("#\t\tRules: read [%d], erroneous [%d], URI (URL|ARGS) [%d]\n",num_rules[NEMESIDA]-newrules,num_errorrules[NEMESIDA]-newerrors,num_URIrules[NEMESIDA]-newurirules);
        fclose(rulesFile);
	}	

    printf("#-----  Statistics (NEMESIDA) ------------------------------\n");
    printf("# Read [%d] nemesida rules, [%d] http-related, [%d] with errors\n", num_rules[NEMESIDA], num_URIrules[NEMESIDA], num_errorrules[NEMESIDA]);
}