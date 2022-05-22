/*
** INSPECTORLOG / MS-INSPECTORLOG
** Todos los derechos reservados
** All rights reserved
**
** Part of INSPECTORLOG tools
**
** Copyright (C) 2022, Jesús E. Díaz Verdejo
** Versión 3.5 JEDV - 20/01/2022
** 
** Changes (last):
**
* 
*	gcc -Wall -g -O0 msctest.c -o msctest -lmodsecurity
*	
*/

#define DEBUG

//C INCLUDES
#include <getopt.h>

//INSPECTORLOG INCLUDES
#include "inspector-common.h"

extern unsigned char ms_conf_file[PATH_MAX+1];		// Modsecurity configuration file
extern bool mslogfile;
extern unsigned char outputms_file[PATH_MAX+1]; 		// Path to output detailed modsecurity log file

bool parse_msArgs(int argc, char **argv){

    bool isOK = true;

    int c;

    /* Flag set by ‘--verbose’. */
    static int verbose_flag;

    if(argc < 3)
        show_mshelp();

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
               {"modsecurity_conf",  required_argument, 1, 'r'},
               {"logtype", required_argument, 0, 't'},
               {"output", required_argument, 0, 'o'},
               {"mslog", required_argument, 0, 'd'},
               {"ealert", no_argument, 0, 'e'},
//               {"nocase", no_argument, 0, 'n'},
               {"warnings",no_argument, 0, 'w'},
			   {"resp_code", no_argument, 0, 'c'},
			   {"labels", no_argument, 0, 'b'},
               {0, 0, 0, 0}
             };
           /* getopt_long stores the option index here. */
           int option_index = 0;


        c = getopt_long(argc, argv, "hl:r:t:o:d:ewcb", long_options, &option_index);

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
            case 'd':
                strncpy((char *)&outputms_file, optarg, PATH_MAX);
                mslogfile = true;
                break;
			case 'r':
               //printf ("option -d with value `%s'\n", optarg);
                strncpy((char*)&ms_conf_file, optarg, PATH_MAX);
               break;
/*            case 'n':
               nocase = true;
               break;
*/
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
				show_mshelp();
				break;
            default:
               show_mshelp();
			case 'b':
				uri_labels = true;
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

void show_mshelp(){

    printf("FORMAT: ms-inspectorlog -l logFile [-t <list|elist|apache|wellness|uri>] -r modsecurity_conf_file  [-o <clean log output>] [-e (extended_alerts)] [-w (encoding warnings)] [-c (response code filtering)] [-b (labeled uris)] [-d <detailed log output>\n");

    exit(EXIT_SUCCESS);
}

