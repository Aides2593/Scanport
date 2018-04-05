#include <windows.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>


#pragma once;
#define LOG_FILE _T("ScanLog.txt")
#define MAX_FILE_SIZE 10485760


void Log(LPSTR format, ...);
void LogW(LPWSTR format, ...);
