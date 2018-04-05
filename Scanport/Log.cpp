#include "Log.h"

void Log(LPSTR format, ...)
{
	CHAR buffer[1024];
	va_list args;
	va_start(args, format);
	vsprintf_s(buffer, format, args);
	va_end(args);
#ifdef DBG_FILE
	HANDLE hFile = CreateFile(LOG_FILE, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() != ERROR_FILE_NOT_FOUND)
		{
			OutputDebugString(_T("Cannot open log file"));
			return;
		}
		hFile = CreateFile(LOG_FILE, GENERIC_ALL, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			OutputDebugString(_T("Cannot create new log file"));
			return;
		}
		//GetFileSize
		DWORD dwFileSize = GetFileSize(hFile, NULL);
		if (dwFileSize == INVALID_FILE_SIZE || dwFileSize > MAX_FILE_SIZE)
			if (SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
				goto FINAL;
		DWORD dwNOBW;
		CHAR szWriteBuffer[1024 * 2];
		CStringA time = CTime::GetCurrentTime().Format("%Y %m %d %H:%M:%S")
			vsprintf(szWriteBuffer, "[%s] %s\n", time, buffer);
		if (WriteFile(hFile, buffer, strlen(szWriteBuffer), &dwNOBW, NULL) == FALSE || dwNOBW != strlen(szWriteBuffer))
		{
			OutputDebugString(_T("WriteFile error!!"));
			goto FINAL;
		}
	FINAL:
		if (hFile)
			CloseHandle(hFile);
		return;
	}

#endif
#ifdef DEBUG
	OutputDebugStringA(buffer);
#endif
}
void LogW(LPWSTR format, ...)
{
	WCHAR buffer[1024];
	va_list args;
	va_start(args, format);
	wvsprintf(buffer, format, args);
	va_end(args);
#ifdef DBG_FILE
	HANDLE hFile = CreateFile(LOG_FILE, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() != ERROR_FILE_NOT_FOUND)
		{
			OutputDebugString(_T("Cannot open log file"));
			return;
		}
		hFile = CreateFile(LOG_FILE, GENERIC_ALL, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			OutputDebugString(_T("Cannot create new log file"));
			return;
		}
		//GetFileSize
		DWORD dwFileSize = GetFileSize(hFile, NULL);
		if (dwFileSize == INVALID_FILE_SIZE || dwFileSize > MAX_FILE_SIZE)
			if (SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
				goto FINAL;
		DWORD dwNOBW;
		WCHAR szWriteBuffer[1024 * 2];
		CString time = CTime::GetCurrentTime().Format("%Y %m %d %H:%M:%S")
			vsprintf(szWriteBuffer, "[%s] %s\n", time, buffer);
		if (WriteFile(hFile, buffer, wcstrlen(szWriteBuffer) * sizeof(WCHAR), &dwNOBW, NULL) == FALSE || dwNOBW != wcslen(szWriteBuffer) * sizeof(WCHAR))
		{
			OutputDebugString(_T("WriteFile error!!"));
			goto FINAL;
		}
	FINAL:
		if (hFile)
			CloseHandle(hFile);
		return;
	}

#endif
#ifdef DEBUG
	OutputDebugStringW(buffer);
#endif
}
