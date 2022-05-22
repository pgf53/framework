#ifndef __INSPECTOR
#define __INSPECTOR

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
** 
*/
#include "inspector-common.h"

/* Structures (inspectorlog): rules related */

typedef struct{
    int negated;               		// Negated expression (uses '!')
    unsigned char * regExp;			// Regular expression
    unsigned char * modifier;		// Modifiers of the regular expression
	pcre *pattern;
}_pcre;								// pcre structure

typedef struct{
    int negated;					// Negated pattern
    unsigned char * pattern_str;	// Pattern to search for
    bool nocase;					// No case switch (per rule basis)
}_uriPattern;						// Pattern to compare

typedef struct{

    // Strings (content or pcre)
    int num_patt;                           // Number of patterns
    _uriPattern URI_pattern[MAX_PATTERNS];  // Till 'MAX_PATTERNS' different patterns, each with different modifiers 
    int num_pcre;                           // Number of regular expressions (only one PCRE per rule accepted in Snort) 
    _pcre pcre[MAX_PCRE];                   // Regular expressions
	char * DURL;							// $URL string

    // Modifiers (snort)
    int urilen;                             // URI length 
    int uritype;                            // Comparison operation: 0=void, 1=lower, 2=greater, 3=equal
	bool WLr;								// White list rule
	
	// Modifiers (nemesida)
	bool url_rule;							// Whole URI rule
	bool var_rule;							// Only args rule
	bool durl_rule;							// Specific URL required rule 

    // Aditional information 

    int num_ref;                            // Number of references
    unsigned char * references[MAX_REFERENCES]; // References to the solution
    unsigned char * attack_type;            // Class of the associated attack
    unsigned char * description;            // Message description of the rule
	int score;								// Score of the rule (nemesida) or priority (Snort)

    // Identifiers
    int sid;                                // Unique identifier of the rule
	int engineid;							// Rule's source

} URI_rule;									// Stored RULE

// GLOBAL VARIABLES (specific for inspectorlog)

// Options

extern int rule_type;						// Type/format of used rules (0 = Snort, 1 = Nemesida, 2 = Mixed)
extern bool rules_snort;					// Load/use snort rules
extern bool rules_nem;						// Load/user nemeside rules

// Files/Input/Output

extern unsigned char rules_path_snort[PATH_MAX+1];  // Path to rules directory (snort)
extern unsigned char rules_path_nem[PATH_MAX+1];    // Path to rules file (nemesida)

// Counters

extern int num_rules[NSIDS+1];			// Number of loaded rules (active) - [0] total, [i] per source
extern int num_URIrules[NSIDS+1];		// Number of URI related rules 
extern int num_errorrules[NSIDS+1];		// Number of rules with parsing errors (dismissed)
extern int num_rules_file;				// Number of read rules for current file

// Rules
extern URI_rule * URI_rules[MAX_URI_RULES]; 

/* Public functions prototypes  */

/* inspector.c */

unsigned char *uchar_malloc(int num_bytes);

/* engine.c */

bool decodespaces_uri(char *str);
int detect_URI(const char * URI, int * rules_detected);

/* logs.c */

void scan_logFile(const char *fileName);

/* rules.c */

void load_rules_snort(char *r_path);
void load_rules_nemesida(char *r_path);
void free_rule(URI_rule * rule);

/* arguments.c */

bool parse_clArgs(int argc, char **argv);
void show_help();

#endif
