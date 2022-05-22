/*
** INSPECTORLOG
** Todos los derechos reservados
** All rights reserved
**
** Copyright (C) 2017, Jesús E. Díaz Verdejo
** Version 3.4 JEDV - 25/11/2021
** Version 3.0 JEDV - 19/12/2017
** 
*/

#define DEBUG

//C INCLUDES
#include <getopt.h>

//INSPECTORLOG INCLUDES
#include "inspector.h"

// Parse command line arguments

bool parse_clArgs(int argc, char **argv){

    bool isOK = true;

    int c;

    /* Flag set by ‘--verbose’. */
    static int verbose_flag;

    if(argc < 3)
        show_help();

    while (1){

        static struct option long_options[] =
             {
               /* These options set a flag. */
               {"verbose", no_argument,       &verbose_flag, 1},
               {"brief",   no_argument,       &verbose_flag, 0},

               /* These options don't set a flag.
                  We distinguish them by their indices. */
               {"help",  no_argument,       0, 'h'},
               {"log_file",  required_argument, 0, 'l'},
               {"snort_rules_dir",  required_argument, 0, 'r'},
               {"logtype", required_argument, 0, 't'},
               {"output", required_argument, 0, 'o'},
               {"nemeside_rules", required_argument, 0, 'm'},
               {"ealert", no_argument, 0, 'e'},
               {"nocase", no_argument, 0, 'n'},
               {"warnings",no_argument, 0, 'w'},
			   {"resp_code", no_argument, 0, 'c'},
			   {"labels", no_argument, 0, 'b'},
               {0, 0, 0, 0}
             };
           /* getopt_long stores the option index here. */
           int option_index = 0;


        c = getopt_long(argc, argv, "hl:r:t:o:m:enwcb", long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

#ifdef DEBUG
            printf("Option detected %c, %s\n",c,optarg);
#endif        
        switch (c){

            case 0:
                /* If this option set a flag, do nothing else now. */
               if (long_options[option_index].flag != 0)
                    break;

               printf ("option %s", long_options[option_index].name);
               if (optarg) 
                    printf (" with arg %s", optarg);
               printf ("\n");
               break;
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
                    printf("InspectorLog: log format [%s] not recognized\n",optarg);
                    exit(-1);
                }
                break;
            case 'o':
                strncpy((char *)&output_file, optarg, PATH_MAX);
                outputf = true;
                break;
            case 'r':
               //printf ("option -d with value `%s'\n", optarg);
			    rules_snort = true;
                strncpy((char*)&rules_path_snort, optarg, PATH_MAX);
               break;
            case 'm':
				rules_nem = true;
                strncpy((char*)&rules_path_nem, optarg, PATH_MAX);
               break;
            case 'n':
               nocase = true;
               break;
            case 'e':
               ealert = true;
               break;
            case 'w':
               warns = true;
               break;
			case 'c':
				resp_code = true;
				break;
			case 'h':
				show_help();
				break;
			case 'b':
				uri_labels = true;
			default:
               show_help();

        }
    }
#ifdef DEBUG
    printf(">> Command line arguments processed ...\n");
#endif
       /* Instead of reporting ‘--verbose’
          and ‘--brief’ as they are encountered,
          we report the final status resulting from them. */
       if (verbose_flag)
         puts ("verbose flag is set");

    /* Print any remaining command line arguments (not options). */
    if (optind < argc){
           printf ("[parse_clArgs] Argument(s) erroneous: ");
           while (optind < argc)
             printf ("%s ", argv[optind++]);
           putchar ('\n');
    }

    return isOK;
}

void show_help(){

    printf("FORMAT: inspectorlog -l logFile [-t <list|elist|apache|wellness|uri>] [-r ruleDir(snort)] [-m rulefile (nemeside)] [-o <clean log output>] [-n (nocase)] [-e (extended_alerts)] [-w (encoding warnings)] [-c (response code filtering)] [-b (labeled uris)]\n");

    exit(EXIT_SUCCESS);
}


