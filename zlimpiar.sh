#!/bin/sh

#### Cargar configuracion
. ./framework_config_interna.conf


rm -rf "${PATH_LOG}"/*
rm -rf "${DIROUT_INDEX}"/*
rm -rf "${DIROUT_ATTACKS}"/*
rm -rf "${DIROUT_CLEAN}"/*
rm -rf "entradas_finalizadas"/*
rm -rf "${RESULTADOS}"/*

