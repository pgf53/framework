# Makefile for INSPECTORLOG
#/********************************************************/
#/* (c) - JEDV			                             */
#/********************************************************/
#/* Makefile                                             */
#/*                                                      */
#/********************************************************/

.KEEP_STATE:

DESTDIR = /home/jedv/work/siva/bin

IHEADS = inspector.h inspector-common.h arguments.h
MHEADS = inspector-common.h ms-arguments.h
PROGS = inspectorlog ms-inspectorlog log-to-tablog

IOBJS = logs.o rules.o arguments.o engine.o scan-logfile.o
ICES = $(IOBJS:%.o=%.c)

MOBJS = logs.o ms-arguments.o ms-scan-logfile.o
MCES = $(MOBJS:%.o=%.c)

#CFLAGS  =  -ggdb -I/usr/include -I/usr/local/include -I. -W -Wreturn-type -Wformat -Wchar-subscripts -Wuninitialized -Wshadow -Wpointer-arith 
CFLAGS  =  -std=c99 -I. -I/usr/local/modsecurity/include -w -O3 -W -Wreturn-type -Wformat -Wchar-subscripts -Wuninitialized -Wshadow -Wpointer-arith

CC      = gcc

# Opciones de compilacion

ILDFLAGS =  -ldl -lpcre -lpthread 
MLDFLAGS = -lm -lstdc++ -lrt -lmodsecurity 

LD_RUN_PATH = /usr/local/lib
MLD_RUN_PATH =  /usr/local/modsecurity/lib 

all:  $(PROGS)


#$(PROGS) : ${CES} ${OBJS} ${PROGS}.c
inspectorlog :  ${ICES} ${IHEADHS} inspectorlog.c
	$(CC) ${CFLAGS}  ${ICES} -o $@ $@.c  ${ILDFLAGS}

ms-inspectorlog :  ${MOBJS} ${MHEADHS} ms-inspectorlog.c
	$(CC) ${CFLAGS}  ${MCES} -o $@ $@.c  ${MLDFLAGS}  -L ${MLD_RUN_PATH}
	
log-to-tablog: logs.o ${MHEADHS} log-to-tablog.c
	$(CC) ${CFLAGS}  logs.o -o $@ $@.c  ${ILDFLAGS}

clean:
	rm -f core *% *.o  $(PROGS) $(PROGS:%=%.exe) ${IOBJS} ${MOBJS}


install:
	cp $(PROGS) $(DESTDIR)

