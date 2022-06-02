/*
** INSPECTORLOG
** Todos los derechos reservados
** All rights reserved
**
** Copyright (C) 2017, Jesús E. Díaz Verdejo
** Versión 3.4 JEDV - 25/11/2021
** Versión 3.0 JEDV - 19/12/2017
** 
*/

#ifndef __ARGUMENTS
#define __ARGUMENTS

//C INCLUDES
#define WLENGTH 128

#include <stdbool.h>

bool parse_clArgs(int argc, char **argv);
bool parse_msArgs(int argc, char **argv);

void show_help();
void show_mshelp();

#endif

