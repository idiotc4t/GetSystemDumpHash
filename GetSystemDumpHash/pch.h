#ifndef PCH_H
#define PCH_H
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include "CheckPriv.h"
#include "PrivEsca.h"
#include "CheckVitualMachine.h"

#pragma comment(linker,"/subsystem:\"Windows\" /ENTRY:\"mainCRTStartup\"")
#endif