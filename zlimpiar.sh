#!/bin/sh

#### Cargar configuracion
. ./framework_config.sh
. ./framework_config_interna.sh


rm -rf "${PATH_LOG}"/*
rm -rf "${DIROUT_INDEX}"/*
rm -rf "${DIROUT_ATTACKS}"/*
rm -rf "${DIROUT_CLEAN}"/*
rm -rf "entradas_finalizadas"/*

