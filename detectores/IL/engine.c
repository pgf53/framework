/*
** INSPECTORLOG
** Todos los derechos reservados
** All rights reserved
**
**
** Copyright (C) 2017, Jesús E. Díaz Verdejo
** Version 3.5 JEDV - 29/03/2022
** Versión 3.4 JEDV - 25/11/2021
** Versión 3.0 JEDV - 19/12/2017
** 
** CHANGES:
**  v3.5: added various utf8 codes (3 parts), mainly spanish related (windows) codes
**  v3.5: urldecode rearranged not to use tables -> direct evaluation from chars
**  v3.5: double encoding in one pass
**	v3.5: Bug fix: infinity loop when URI ends in %25....25
**	v3.5: Bug fix: negated content now correctly processed
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

// Longer sequences must be placed first (sequential search)

char *utfescaped [] = { // upercase
						"%E2%82%AC", "%E2%80%9A", "%E2%80%9E", "%E2%80%A6", "%E2%80%A0", "%E2%80%A1", "%E2%80%B0", "%E2%80%B9", "%E2%80%98", "%E2%80%99", 
						"%E2%80%9C", "%E2%80%9D", "%E2%80%A2", "%E2%80%93", "%E2%80%94",
						"%C6%92", "%CB%86", "%C5%A0", "%C5%92", "C5%8D", "%C5%BD", "%C2%90", "%CB%9C", "%E2%84", "%C5%A1",
						"%E2%80", "%C5%93", "%C5%BE", "%C5%B8", "%C2%A0", "%C2%A1", "%C2%A2", "%C2%A3", "%C2%A4", "%C2%A5",
						"%C2%A6", "%C2%A7", "%C2%A8", "%C2%A9", "%C2%AA", "%C2%AB", "%C2%AC", "%C2%AD", "%C2%AE", "%C2%AF",
						"%C2%B0", "%C2%B1", "%C2%B2", "%C2%B3", "%C2%B4", "%C2%B5", "%C2%B6", "%C2%B7", "%C2%B8", "%C2%B9",
						"%C2%BA", "%C2%BB", "%C2%BC", "%C2%BD", "%C2%BE", "%C2%BF", "%C3%80", "%C3%81", "%C3%82", "%C3%83",
						"%C3%84", "%C3%85", "%C3%86", "%C3%87", "%C3%88", "%C3%89", "%C3%8A", "%C3%8B", "%C3%8C", "%C3%8D",
						"%C3%8E", "%C3%8F", "%C3%90", "%C3%91", "%C3%92", "%C3%93", "%C3%94", "%C3%95", "%C3%96", "%C3%97",
						"%C3%98", "%C3%99", "%C3%9A", "%C3%9B", "%C3%9C", "%C3%9D", "%C3%9E", "%C3%9F", "%C3%A0", "%C3%A1",
						"%C3%A2", "%C3%A3", "%C3%A4", "%C3%A5", "%C3%A6", "%C3%A7", "%C3%A8", "%C3%A9", "%C3%AA", "%C3%AB", 
						"%C3%AC", "%C3%AD", "%C3%AE", "%C3%AF", "%C3%B0", "%C3%B1", "%C3%B2", "%C3%B3", "%C3%B4", "%C3%B5", 
						"%C3%B6", "%C3%B7", "%C3%B8", "%C3%B9", "%C3%BA", "%C3%BB", "%C3%BC", "%C3%BD", "%C3%BE", "%C3%BF"
					};
					
char *utfescapedl [] = { // lowercase
						"%e2%82%ac", "%e2%80%9a", "%e2%80%9e", "%e2%80%a6", "%e2%80%a0", "%e2%80%a1", "%e2%80%b0", "%e2%80%b9", "%e2%80%98", "%e2%80%99", 
						"%e2%80%9c", "%e2%80%9d", "%e2%80%a2", "%e2%80%93", "%e2%80%94",
						"%c6%92", "%cb%86", "%c5%a0", "%c5%92", "c5%8d", "%c5%bd", "%c2%90", "%cb%9c", "%e2%84", "%c5%a1",
						"%e2%80", "%c5%93", "%c5%be", "%c5%b8", "%c2%a0", "%c2%a1", "%c2%a2", "%c2%a3", "%c2%a4", "%c2%a5",
						"%c2%a6", "%c2%a7", "%c2%a8", "%c2%a9", "%c2%aa", "%c2%ab", "%c2%ac", "%c2%ad", "%c2%ae", "%c2%af",
						"%c2%b0", "%c2%b1", "%c2%b2", "%c2%b3", "%c2%b4", "%c2%b5", "%c2%b6", "%c2%b7", "%c2%b8", "%c2%b9",
						"%c2%ba", "%c2%bb", "%c2%bc", "%c2%bd", "%c2%be", "%c2%bf", "%c3%80", "%c3%81", "%c3%82", "%c3%83",
						"%c3%84", "%c3%85", "%c3%86", "%c3%87", "%c3%88", "%c3%89", "%c3%8a", "%c3%8b", "%c3%8c", "%c3%8d",
						"%c3%8e", "%c3%8f", "%c3%90", "%c3%91", "%c3%92", "%c3%93", "%c3%94", "%c3%95", "%c3%96", "%c3%97",
						"%c3%98", "%c3%99", "%c3%9a", "%c3%9b", "%c3%9c", "%c3%9d", "%c3%9e", "%c3%9f", "%c3%a0", "%c3%a1",
						"%c3%a2", "%c3%a3", "%c3%a4", "%c3%a5", "%c3%a6", "%c3%a7", "%c3%a8", "%c3%a9", "%c3%aa", "%c3%ab", 
						"%c3%ac", "%c3%ad", "%c3%ae", "%c3%af", "%c3%b0", "%c3%b1", "%c3%b2", "%c3%b3", "%c3%b4", "%c3%b5", 
						"%c3%b6", "%c3%b7", "%c3%b8", "%c3%b9", "%c3%ba", "%c3%bb", "%c3%bc", "%c3%bd", "%c3%be", "%c3%bf"
					};
					
char *utfunescaped[] = { 
						"€", "‚", "„", "…", "†","‡", "‰", "‹", "‘", "’",
						"“", "”", "•", "–", "—", 
						"ƒ", "ˆ", "Š", "Œ", "%8D", "Ž", "%90", "˜%98˜˜˜˜", "™", "š",
						"›", "œ", "ž", "Ÿ", "%A0", "¡", "¢", "£", "¤", "¥", 
						"¦", "§", "¨", "©", "ª", "«", "¬", "%AD", "®", "¯",
						"°", "±", "²", "³", "´", "µ", "¶", "·", "¸", "¹",
						"º", "»", "¼", "½", "¾", "¿","À", "Á", "Â", "Ã", 
						"Ä", "Å", "Æ", "Ç", "È", "É", "Ê", "Ë", "Ì", "Í",
						"Î", "Ï", "Ð", "Ñ", "Ò", "Ó", "Ô", "Õ", "Ö", "×", 
						"Ø", "Ù", "Ú", "Û", "Ü", "Ý", "Þ", "ß", "à", "á", 
						"â", "ã", "ä", "å", "æ", "ç", "è", "é", "ê", "ë",
						"ì", "í", "î", "ï", "ð", "ñ", "ò", "ó", "ô", "õ",
						"ö", "÷", "ø", "ù", "ú", "û", "ü", "ý", "þ", "ÿ"
					};

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

int hex2int(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    return -1;
}

/*
// Stops at any null characters.
int decode_utf8_char(char **s) {
  int k = **s ? __builtin_clz(~(**s << 24)) : 0;  // Count # of leading 1 bits.
  int mask = (1 << (8 - k)) - 1;                  // All 1's with k leading 0's.
  int value = **s & mask;
  for (++(*s), --k; k > 0 && **s; --k, ++(*s)) {  // Note that k = #total bytes, or 0.
    value <<= 6;
    value += (**s & 0x3F);
  }
  return value;
}
*/

// This is generating core dumps, gonna try an alternative: urldecode and next parse utf8 encoding as chars (should work) 

bool utf8decode(char *utfstr) {
    int i,j;
    char tmpc[URILENGTH+1];
    char *p, *q, *f;
    bool found = false;

	if (strstr(utfstr,"%")) {
		strncpy(tmpc,utfstr,URILENGTH);

#ifdef DEBUG2
		printf("%d %d %s\n",nutf8, sizeof(utfescaped),tmpc);
#endif
		for(i=0;i< nutf8; i++) {
		   
			while ((p = strstr(tmpc,utfescaped[i])) || (q = strstr(tmpc,utfescapedl[i]))) {
				found = true;
				if (q != NULL) p = q;
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
	}
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
    found = false;
       
    while (*p != '\0') {
        if (*p == '%')  {
            strncpy(code,p,3);
            code[3]='\0';
            found = false;
            j = 0;
            
            /* Optimization: %2525 particular case (multiple encoding of %) */

			if ( (p[0] == '%') && (p[1] == '2') && (p[2] == '5')){
                p += 3;
                while( (p[0] == '2') && (p[1] == '5')) p+=2;
                *f = '%';
                
                // Decode again %
                
                if (p[1] != '\0') {
                  if (p[2] != '\0') {
					*f = (char)( ((int)p[1])-((int)'0') )*16 + (((int)p[2])-((int)'0'));
					p += 2;
					f++;  
				  } else {
					  *f = '\0';
					  p += 2;
				  }
				} else {
					*f = '\0';
					p += 1;
				}
            } else {

				*f = (char)(hex2int(p[1])*16 + hex2int(p[2]));
				f++;
				p +=3;
            }
            found = true;
        } else {
            *f++ = *p++;
            *f = '\0';
        }
    }
	*f = '\0';
	
	// Check for an ending % or %?
	
	if (*(f-1) == '%') *(f-1) = '\0';
	if (*(f-2) == '%') *(f-2) = '\0';	// This assumes URI is truncated at an incorrect position
	
	
    strcpy(str,tmpchar);
    return(found);   
}

#undef DEBUG2
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
        } else if ( (pos != NULL) && (rule->URI_pattern[i].negated)) {
#ifdef DEBUG 
            printf(" fail\n");
#endif
            match = false;
            break;				
#ifdef DEBUG
		} else
			printf(" ok\n");
#else
        } 
#endif

    }

    // Matching also applies to regular expression in "pcre" format

    if (match && rule->num_pcre){ 	// Whether all literal patterns have been found
	
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
//		Removed as they are redundant - Will be decoded and procesed in the second step
//		utf8 = utf8decode(path);
//		if (query[0] != '\0') utf8 = utf8decode(query);
	
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
        printf("BEFORE UFT8:   [%s]\n",tmpuri);
#endif 
    utf8 = utf8decode(tmpuri);
	if (rules_nem) { // Decode also path and query independently
		utf8 = utf8decode(path);
		if (query[0] != '\0') utf8 = utf8decode(query);
	};

#ifdef DEBUG2
        printf("BEFORE:   [%s]\n",tmpuri);
#endif

     while (strstr(tmpuri,"%") ) {
        
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

