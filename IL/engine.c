/*
** INSPECTORLOG
** Todos los derechos reservados
** All rights reserved
**
**
** Copyright (C) 2017, Jesús E. Díaz Verdejo
** Versión 3.4 JEDV - 25/11/2021
** Versión 3.0 JEDV - 19/12/2017
** 
** CHANGES:
**	v3.4: Added support por $URL rules from nemesida -> Assumed NEMESIDA rules just include a single pattern (plus $URL pattern, if any) to handle $URL rules
**	v3.4: Added function decodespaces_uri
**	v3.4: Removed function unescape_uri - Not used
**	v3.4: Support for nemesida (path and query handled separatedly, %20 substituted in path and query)
*/

//C INCLUDES
#include <stdbool.h>
#include <stdio.h>

//INSPECTORLOG INCLUDES

#include <inspector.h>

//                        ¡         Á         É          Í         Ó        Ú         Ü          á         é         í           ó      ú         ü          Ñ         ñ            ~      `              ,          º       ª
char *utfescaped [] = { "%C2%A1", "%C3%81",  "%C3%89", "%C3%8D", "%C3%93", "%C3%9A", "%C3%9C", "%C3%A1", "%C3%A9", "%C3%AD", "%C3%B3", "%C3%BA", "%C3%BC", "%C3%91", "%C3%B1", "%CB%9C", "%E2%82%AC", "%E2%80%9A", "%C2%BA", "%C2%AA", "%C2%AD", "%C2%B4",
                        "%c2%a1", "%c3%81",  "%c3%89", "%c3%8D", "%c3%93", "%c3%9A", "%c3%9c", "%c3%a1", "%c3%a9", "%c3%ad", "%c3%b3", "%c3%bA", "%c3%bc", "%c3%91", "%c3%b1", "%cb%9c", "%e2%82%ac", "%e2%80%9a", "%c2%ba", "%c2%aa", "%c2%ad", "%c2%b4",
                        };

char *utfunescaped[] = { "¡", "Á", "É", "Í", "Ó", "Ú", "Ü", "á", "é", "í", "ó", "u", "ü", "Ñ", "ñ", "~", "%80", "%82", "º", "ª", " ", "%B4",
                        "¡", "Á", "É", "Í", "Ó", "Ú", "Ü", "á", "é", "í", "ó", "u", "ü", "Ñ", "ñ", "~", "%80", "%82" , "º", "ª", " " , "%B4" };


char *escaped[]={"%20","%21","%22","%23","%24","%25","%26","%27","%28","%29","%2A","%2B","%2C","%2D","%2E","%2F",
                 "%30","%31","%32","%33","%34","%35","%36","%37","%38","%39","%3A","%3B","%3C","%3D","%3E","%3F",
                 "%40","%41","%42","%43","%44","%45","%46","%47","%48","%49","%4A","%4B","%4C","%4D","%4E","%4F",
                 "%50","%51","%52","%53","%54","%55","%56","%57","%58","%59","%5A","%5B","%5C","%5D","%5E","%5F",
                 "%60","%61","%62","%63","%64","%65","%66","%67","%68","%69","%6A","%6B","%6C","%6D","%6E","%6F",
                 "%70","%71","%72","%73","%74","%75","%76","%77","%78","%79","%7A","%7B","%7C","%7D","%7E",
                 "%80",      "%82","%83","%84","%85","%86","%87","%88","%89","%8A","%8B","%8C",      "%8E",
                       "%91","%92","%93","%94","%95","%96","%97","%98","%99","%9A","%9B","%9C",      "%9E", "%9F",  
                 "%A0","%A1","%A2","%A3","%A4","%A5","%A6","%A7","%A8","%A9","%AA","%AB","%AC",       "%AE","%AF",
                 "%B0","%B1","%B2","%B3","%B4","%B5","%B6","%B7","%B8","%B9","%BA","%BB","%BC","%BD", "%BE","%BF",
                 "%C0","%C1","%C2","%C3","%C4","%C5","%C6","%C7","%C8","%C9","%CA","%CB","%CC","%CD", "%CE","%CF",
                 "%D0","%D1","%D2","%D3","%D4","%D5","%D6","%D7","%D8","%D9","%DA","%DB","%DC","%DD", "%DE","%DF",
                 "%E0","%E1","%E2","%E3","%E4","%E5","%E6","%E7","%E8","%E9","%EA","%EB","%EC","%ED", "%EE","%EF",
                 "%F0","%F1","%F2","%F3","%F4","%F5","%F6","%F7","%F8","%F9","%FA","%FB","%FC","%FD", "%EF","%FF",

//                 "%2a","%2b","%2c","%2d","%2e","%2f",
//                 "%3a","%3b","%3c","%3d","%3e","%3f",
//                 "%4a","%4b","%4c","%4d","%4e","%4f",
//                 "%5a","%5b","%5c","%5d","%5e","%5f",
//                 "%6a","%6b","%6c","%6d","%6e","%6f",                 
//                 "%7a","%7b","%7c","%7d","%7e",
                 "%0A","%0D","%0a","%0d"};
char *unescaped[]={" ","!",  "\"", "#",  "$",  "%",  "&",  "'",  "(",  ")",  "*",  "+",  ",",  "-",  ".",  "/",  
                 "0","1","2","3","4","5","6","7","8","9",":",  ";",  "<",  "=",  ">",  "?",  
                 "@","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O",  
                 "P","Q","R","S","T","U","V","W","X","Y","Z", "[",  "\\", "]",  "^",  "_",  
                 "`","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o", 
                 "p","q","r","s","t","u","v","w","x","y","z","{",  "|",  "}",  "~", 
                 "‚",    "ƒ","„","†","‡","^","‰","Š","‹","Œ",   "Ž",  
                 "‘", "’", "“", "”", "•", "–", "—", "˜", "™", "š", "›", "œ", "ž", "Ÿ",
                 " ","¡", "¢", "£", "¤","¥","¦","§","¨","©","ª","«","¬","­","®", "¯",
                 "°","±","²","³","´","µ","¶","·","¸","¹","º","»","¼","½","¾","¿", 
                 "À","Á","Â","Ã","Ä","Å","Æ","Ç","È","É","Ê","Ë","Ì","Í","Î","Ï",  
                 "Ð","Ñ","Ò","Ó","Ô","Õ","Ö","×","Ø","Ù","Ú","Û","Ü","Ý","Þ","ß",  
                 "à","á","â","ã","ä","å","æ","ç","è","é","ê","ë","ì","í","î","ï",                 
                 "ð","ñ","ò","ó","ô","õ","ö","÷","ø","ù","ú","û","ü","ý","þ","ÿ",
//                 "*",  "+",  ",",  "-",  ".",  "/",  
//                 ":",  ";",  "<",  "=",  ">",  "?",  
//                 "J","K","L","M","N","O",
//                 "Z","[",  "\\", "]",  "^",  "_", 
//                 "j","k","l","m","n","o",                 
//                 "z","{",  "|",  "}",  "~",
                 "\n","\n","\n","\n","A"};

#define nescapes (sizeof(escaped) / sizeof(const char *))
#define nutf8 (sizeof(utfescaped) / sizeof(const char *))

// Changes all escaped spaces for its ascii version 

bool decodespaces_uri(char *str) {
    char tmpchar[URILENGTH+1];
    char *p, *f;
    tmpchar[0] = '\0';
    p = str;
    f = tmpchar;
    
    while (*p != '\0') {
        if (*p == '%')  {
			if (p[1] == '2' && p[2] == '0') { 
				*f = ' ';
				p += 3;
				f++;
			} else {
				*f++ = *p++;
				*f = '\0';
			}
        } else {
            *f++ = *p++;
            *f = '\0';
        }
    }
    strcpy(str,tmpchar);
    return(false);   
}

bool utf8decode(char *utfstr) {
    int i,j;
    char tmpc[URILENGTH+1];
    char *p, *f;
    bool found;

    strncpy(tmpc,utfstr,URILENGTH);

#ifdef DEBUG2
	printf("%d %d %d %s\n",nutf8,nescapes, sizeof(utfescaped),tmpc);
#endif
    for(i=0;i< nutf8; i++) {
       
        while (p = strstr(tmpc,utfescaped[i])) {
            found = true;
#ifdef DEBUG
            printf("Found [%s]\n",utfescaped[i]);
#endif
            f = p+strlen(utfescaped[i]);

            j=0;
            while (j < strlen(utfunescaped[i])) {
                *p++ = utfunescaped[i][j++];
            }
            
            while (*f != '\0') *p++ = *f++;
            *p = '\0';             
        }

    }
                
    if (found) strcpy(utfstr,tmpc);

 return found;
}    

bool urldecode(char *str) {
    int i, j;
    bool found;
    char tmpchar[URILENGTH+1];
    char code[4];
    char *p, *f;
    
    tmpchar[0] = '\0';
    p = str;
    f = tmpchar;
       
    while (*p != '\0') {
        if (*p == '%')  {
            strncpy(code,p,3);
            code[3]='\0';
            found = false;
            j = 0;
            
            /* Optimization: %2525 particular case (multiple encoding of %) */

            if (!strncmp(code,"%25",3) ) {
                p += 3;
                while( (p[0] == '2') && (p[1] == '5')) p+=2;
                *f = '%';
                f++;
            } else {
                
                while ((j < nescapes) && !found ) {
                    if (!strncasecmp(escaped[j],code,3)) {
                        strcat(tmpchar,unescaped[j]);
                        found = true;
                        p += 3;
                        f += strlen(unescaped[j]);
                    } else j++;
                }
                if ((!found)) {
                    if (warns) printf("[urldecode] WARNING Error decoding [%s] in uri [%s] \n",code,str);
                    return(true);
                }
            }
        } else {
            *f++ = *p++;
            *f = '\0';
        }
    }
    strcpy(str,tmpchar);
    return(false);   
}

#undef DEBUG
//Return 'true' if the given 'URI' matches the given 'rule'
bool check_URIpatterns(char * URI, URI_rule * rule){

    bool match = true;
    char *pos = NULL;
    int OVECCOUNT = 1024;
    int ovector[OVECCOUNT];
	int offset;
	int p=0, i=0;

    /* Check urilen */

    if ((rule->uritype == URILENEQ) && (rule->urilen != strlen(URI))) return(false);
    if ((rule->uritype == URILENLT) && (rule->urilen < strlen(URI))) return(false);
    if ((rule->uritype == URILENGT) && (rule->urilen > strlen(URI))) return(false);

#ifdef DEBUG2
    printf("Applying rule [%d]\n",rule->sid);
#endif

    // For a rule to be matched, it must contain all the patterns in the rule
	
	for(i=0; i<rule->num_patt; i++){
#ifdef DEBUG
        printf("Checking string [%s] with pattern content [%s] (negated=%d)-> ",URI, rule->URI_pattern[i].pattern_str,rule->URI_pattern[i].negated);
#endif
        if ((rule->URI_pattern[i].nocase) || (nocase)) {
            pos = strcasestr(URI, rule->URI_pattern[i].pattern_str);
        } else {     
            pos = strstr(URI, rule->URI_pattern[i].pattern_str);
        }
        if ( (pos == NULL) && !(rule->URI_pattern[i].negated)) {
#ifdef DEBUG 
            printf(" fail\n");
#endif
            match = false;
            break;
#ifdef DEBUG
        } else printf(" ok\n");
#else
        } 
#endif

    }

    // Matching also applies to regular expression in "pcre" format

    if(match && rule->num_pcre){ 	// Whether all literal patterns have been found
	
        match = true;
        
#ifdef DEBUGTIME
            timeinfo = localtime(&rawtime);
            printf("-> PCRE Expression [%d of %d] = \"%s\"\n", p, rule->num_pcre, asctime(timeinfo));
#endif

        for (p=0;p < ((rule->num_pcre) && (match == true)); p++) { /* Check all regular expressions */
       
#ifdef DEBUGTIME
            time(&rawtime);
            printf("-> PCRE Expression [%d of %d] SID (%d)= \"%s\"\n", p, rule->num_pcre, rule->sid, ctime(&rawtime));
#endif        
#ifdef DEBUG
                printf("Checking [%s] with pcre expression [%s]\n",URI,rule->pcre[p].regExp);
#endif

                offset = pcre_exec(
                    rule->pcre[p].pattern,              /* the compiled pattern */
                    NULL,                    /* no extra data - pattern was not studied */
                    URI,                  /* the string to match */
                    strlen(URI),          /* the length of the string */
                    0,                    /* start at offset 0 in the subject */
                    0,                    /* default options */
                    ovector,              /* output vector for substring information */
                    OVECCOUNT);           /* number of elements in the output vector */

                if ((offset < 0) && !rule->pcre[p].negated) {
                    match = false;
                }
        }
    }

    return match;
}

//Return the number of positives matches for the given 'URI' against the actually loaded rules
int detect_URI(const char * URI, int * rules_detected){

    int positives = 0;
    int j=0, n=0;
	bool detected = false, detectedq = false, found;
    char tmpuri[URILENGTH], path[URILENGTH], query[URILENGTH];
    bool utf8= false, urlcoded = false, pathencoded = false;          /* Check for the presence of % */
	char *q;
    
	/* Handle URI and split */
    
	strcpy(tmpuri,URI);		// Preserve original URI
	path[0]='\0';
	query[0] = '\0';
	if (rules_nem) { 		// Split path and query for NEMESIDA
		q = strchr(tmpuri,'?'); // TODO: Watch out for possible ? in path ... Just the first found is considered
		if (q) {
			strncpy(path,tmpuri, q-tmpuri);
			path[q-tmpuri]='\0';
			strcpy(query,q+1);
		} else strcpy(path, tmpuri);
	};

	/* Nemesida seems to decode utf and %20 before applying rules ... check and eliminate from path and query */
	/* Checked inconsistent managmement of %20 ... there is a rule with explicit %20 */
	/* Proposed (DONE): to apply decodespaces_uri to nemesida rules */
	
	if (rules_nem) { // Decode also path and query independently
		utf8 = utf8decode(path);
		if (query[0] != '\0') utf8 = utf8decode(query);
	
		// Not sure on how to handle %20 - conflicting behaviour for rules 2712 and 1063 - See previous comments
		decodespaces_uri(path);
		decodespaces_uri(query);
	};
#ifdef DEBUG2
	printf("URI [%s] PATH [%s] QUERY [%s]\n",URI, path, query);
#endif

    /* First phase: check URI as is */
	
    for(n=0; n < num_URIrules[0]; n++){ // Check every rule
		
		// Nemeside process query and path independently
		if (URI_rules[n]->engineid != NEMESIDA) {
			detected = check_URIpatterns(tmpuri, URI_rules[n]);
		} else {
			detected = false;
			detectedq = false;

			if (URI_rules[n]->durl_rule) {		// $URL rule -> SPECIAL CASE

				if (strstr(path, URI_rules[n]->DURL)) {  // First check whether DURL rule accomplish
					if (URI_rules[n]->var_rule == false) { // Not affecting QUERY: just check path
						detected = check_URIpatterns(path, URI_rules[n]);
					} else {	// Need to check query for first rule
						if (query[0] != '\0') {			
							detectedq = check_URIpatterns(query, URI_rules[n]);	
						} else detectedq = false;
					};
				}
			} else {		// NEMESIDA regular rule

				if (URI_rules[n]->url_rule) {
					detected = check_URIpatterns(path, URI_rules[n]);
				};
				if (URI_rules[n]->var_rule) {
					if (query[0] != '\0') {			
						detectedq = check_URIpatterns(query, URI_rules[n]);	
					} else detectedq = false;
				};
			};
		};
		if ( detected || detectedq){
            rules_detected[positives] = n;
            positives++;
        }
    };
	
    /* Check for escaped chars, decode them and check all the rules against (iterate till no % remains */
    
    // First decode utf8decode
  
#ifdef DEBUG2
        printf("BEFORE:   [%s]\n",tmpuri);
#endif 
    utf8 = utf8decode(tmpuri);
	if (rules_nem) { // Decode also path and query independently
		utf8 = utf8decode(path);
		if (query[0] != '\0') utf8 = utf8decode(query);
	};

#ifdef DEBUG2
        printf("BEFORE:   [%s]\n",tmpuri);
#endif

    while (strstr(tmpuri,"%") && !urlcoded) {
        
        urlcoded = urldecode(tmpuri);          /* Step by step decoding (process doble, triple, etc. encoding  */
#ifdef DEBUG2
        printf("AFTER: [%s]\n",tmpuri);
#endif

		if (rules_nem) { 		// Decode path and query
			pathencoded = urldecode(path);
			if (query[0] != '\0') pathencoded = urldecode(query);
		};
		
        for(int n=0; n < num_URIrules[0]; n++){ // Check every rule
			
			// Nemeside process query and path independently

			if (URI_rules[n]->engineid != NEMESIDA) {		// Not NEMESIDA (simpler ...)
				
				detected = check_URIpatterns(tmpuri, URI_rules[n]);
				
			} else {
				detected = false;
				detectedq = false;
				
				if (URI_rules[n]->durl_rule) {		// $URL rule -> SPECIAL CASE

					if (strstr(path, URI_rules[n]->DURL)) {  // First check whether DURL rule accomplish
						if (URI_rules[n]->var_rule == false) { // Not affecting QUERY: just check path
							detected = check_URIpatterns(path, URI_rules[n]);
						} else {	// Need to check query for first rule
							if (query[0] != '\0') {			
								detectedq = check_URIpatterns(query, URI_rules[n]);	
							} else detectedq = false;
						};
					}
					
				} else { 			// Regular NEMESIDA case
					if (URI_rules[n]->url_rule) {
						detected = check_URIpatterns(path, URI_rules[n]);
					}
					if (URI_rules[n]->var_rule) {
						if (query[0] != '\0') {			
							detectedq = check_URIpatterns(query, URI_rules[n]);	
						} else detectedq = false;
					};
				};
			}; 
            if( detected || detectedq ){ // Match, check whether it is a new rule
                found = false;
                for(j=0; j < positives; j++) {
                    if (rules_detected[j] == n) found = true;
                };
                if (!found) {
                    rules_detected[positives] = n;
                    positives++;
                }
            }
        }
    } 
    
    return positives;
}

