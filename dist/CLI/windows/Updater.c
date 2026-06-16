/**
$Id: Updater.c 19355 2026-06-15 14:35:22Z Bear $

Copyright (c) 2026 Nuwa Information Co., Ltd, All Rights Reserved.

Licensed under the Proprietary License,
you may not use this file except in compliance with the License.
You may obtain a copy of the License at our web site.

See the License for the specific language governing permissions and
limitations under the License.

$Author: Bear $
$Date:: 2026-06-15 22:35:22 #$
$Revision: 19355 $
*/
/* cl /nologo /MT /O2 /W4 /std:c11 Updater.c /link /OPT:REF /OPT:ICF /MANIFEST:EMBED /MANIFESTUAC:"level='asInvoker' uiAccess='false'" /OUT:ffl-updater.exe */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef UNICODE
#define UNICODE
#endif

#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <wchar.h>

typedef struct UpdaterOptions
{
 DWORD parentPid;
 const wchar_t *sourcePath;
 const wchar_t *targetPath;
 DWORD timeoutMs;
 DWORD retryDelayMs;
 bool shouldRestart;
 bool keepBackup;
} UpdaterOptions;

static const DWORD DefaultTimeoutMs = 60000;
static const DWORD DefaultRetryDelayMs = 500;

static bool AreStringsEqual(const wchar_t *leftText, const wchar_t *rightText)
{
 return wcscmp(leftText, rightText) == 0;
}

static bool HasNextArgument(int index, int argc)
{
 return index + 1 < argc;
}

static DWORD ParseDword(const wchar_t *text, DWORD fallbackValue)
{
 wchar_t *endPtr = NULL;
 unsigned long value = wcstoul(text, &endPtr, 10);

 if(endPtr == text || *endPtr != L'\0')
 {
  return fallbackValue;
 }

 return (DWORD)value;
}

static bool DoesFileExist(const wchar_t *path)
{
 DWORD attributes = GetFileAttributesW(path);

 return attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static wchar_t *AllocateWideChars(size_t charCount)
{
 return (wchar_t *)calloc(charCount, sizeof(wchar_t));
}

static wchar_t *CreateBackupPath(const wchar_t *targetPath)
{
 const wchar_t *backupSuffix = L".old";
 size_t targetLength = wcslen(targetPath);
 size_t suffixLength = wcslen(backupSuffix);
 size_t bufferLength = targetLength + suffixLength + 1;

 wchar_t *backupPath = AllocateWideChars(bufferLength);

 if(!backupPath)
 {
  return NULL;
 }

 swprintf(backupPath, bufferLength, L"%s%s", targetPath, backupSuffix);

 return backupPath;
}

static wchar_t *CreateRestartCommandLine(const wchar_t *targetPath)
{
 size_t targetLength = wcslen(targetPath);
 size_t bufferLength = targetLength + 3;

 wchar_t *commandLine = AllocateWideChars(bufferLength);

 if(!commandLine)
 {
  return NULL;
 }

 swprintf(commandLine, bufferLength, L"\"%s\"", targetPath);

 return commandLine;
}

static void PrintLastError(const wchar_t *action)
{
 DWORD errorCode = GetLastError();
 wchar_t *message = NULL;

 FormatMessageW(
  FORMAT_MESSAGE_ALLOCATE_BUFFER |
  FORMAT_MESSAGE_FROM_SYSTEM |
  FORMAT_MESSAGE_IGNORE_INSERTS,
  NULL,
  errorCode,
  0,
  (LPWSTR)&message,
  0,
  NULL
 );

 if(message)
 {
  fwprintf(stderr, L"%s failed. Error %lu: %s\n", action, errorCode, message);
  LocalFree(message);
 }
 else
 {
  fwprintf(stderr, L"%s failed. Error %lu\n", action, errorCode);
 }
}

static bool WaitForParentProcess(DWORD parentPid)
{
 if(parentPid == 0)
 {
  return true;
 }

 HANDLE processHandle = OpenProcess(SYNCHRONIZE, FALSE, parentPid);

 if(!processHandle)
 {
  DWORD errorCode = GetLastError();

  if(errorCode == ERROR_INVALID_PARAMETER)
  {
   return true;
  }

  fwprintf(
   stderr,
   L"Could not open parent process %lu. Continue with replace retry loop.\n",
   parentPid
  );

  return true;
 }

 WaitForSingleObject(processHandle, INFINITE);
 CloseHandle(processHandle);

 return true;
}

static bool CreateBackupIfNeeded(const wchar_t *targetPath, const wchar_t *backupPath)
{
 DeleteFileW(backupPath);

 if(!DoesFileExist(targetPath))
 {
  return true;
 }

 if(!CopyFileW(targetPath, backupPath, FALSE))
 {
  PrintLastError(L"CopyFileW backup");
  return false;
 }

 return true;
}

static bool MoveSourceToTarget(const wchar_t *sourcePath, const wchar_t *targetPath)
{
 return MoveFileExW(
  sourcePath,
  targetPath,
  MOVEFILE_REPLACE_EXISTING |
  MOVEFILE_COPY_ALLOWED |
  MOVEFILE_WRITE_THROUGH
 ) != FALSE;
}

static bool ReplaceOnce(const UpdaterOptions *options, const wchar_t *backupPath)
{
 if(!DoesFileExist(options->sourcePath))
 {
  fwprintf(stderr, L"Source file does not exist: %s\n", options->sourcePath);
  return false;
 }

 CreateBackupIfNeeded(options->targetPath, backupPath);

 if(!MoveSourceToTarget(options->sourcePath, options->targetPath))
 {
  return false;
 }

 if(!options->keepBackup)
 {
  DeleteFileW(backupPath);
 }

 return true;
}

static bool ReplaceWithRetry(const UpdaterOptions *options)
{
 wchar_t *backupPath = CreateBackupPath(options->targetPath);

 if(!backupPath)
 {
  fwprintf(stderr, L"Could not allocate backup path.\n");
  return false;
 }

 ULONGLONG deadlineTick = GetTickCount64() + options->timeoutMs;

 while(GetTickCount64() <= deadlineTick)
 {
  if(ReplaceOnce(options, backupPath))
  {
   free(backupPath);
   return true;
  }

  Sleep(options->retryDelayMs);
 }

 PrintLastError(L"Replace target executable");

 free(backupPath);
 return false;
}

static bool RestartTarget(const wchar_t *targetPath)
{
 STARTUPINFOW startupInfo;
 PROCESS_INFORMATION processInfo;
 wchar_t *commandLine = CreateRestartCommandLine(targetPath);

 if(!commandLine)
 {
  fwprintf(stderr, L"Could not allocate restart command line.\n");
  return false;
 }

 ZeroMemory(&startupInfo, sizeof(startupInfo));
 ZeroMemory(&processInfo, sizeof(processInfo));

 startupInfo.cb = sizeof(startupInfo);

 BOOL created = CreateProcessW(
  targetPath,
  commandLine,
  NULL,
  NULL,
  FALSE,
  0,
  NULL,
  NULL,
  &startupInfo,
  &processInfo
 );

 free(commandLine);

 if(!created)
 {
  PrintLastError(L"CreateProcessW restart");
  return false;
 }

 CloseHandle(processInfo.hProcess);
 CloseHandle(processInfo.hThread);

 return true;
}

static void PrintUsage(void)
{
 fwprintf(stderr, L"Usage:\n");
 fwprintf(stderr, L"  ffl-updater.exe --pid <pid> --source <newExe> --target <currentExe> [options]\n\n");
 fwprintf(stderr, L"Options:\n");
 fwprintf(stderr, L"  --restart              Restart target after replacement\n");
 fwprintf(stderr, L"  --timeout-ms <ms>      Max replacement wait time, default 60000\n");
 fwprintf(stderr, L"  --retry-ms <ms>        Retry delay, default 500\n");
 fwprintf(stderr, L"  --keep-backup          Keep <target>.old after success\n");
}

static bool ParseArguments(int argc, wchar_t **argv, UpdaterOptions *options)
{
 options->parentPid = 0;
 options->sourcePath = NULL;
 options->targetPath = NULL;
 options->timeoutMs = DefaultTimeoutMs;
 options->retryDelayMs = DefaultRetryDelayMs;
 options->shouldRestart = false;
 options->keepBackup = false;

 for(int index = 1; index < argc; index++)
 {
  if(AreStringsEqual(argv[index], L"--pid"))
  {
   if(!HasNextArgument(index, argc))
   {
    return false;
   }

   options->parentPid = ParseDword(argv[++index], 0);
   continue;
  }

  if(AreStringsEqual(argv[index], L"--source"))
  {
   if(!HasNextArgument(index, argc))
   {
    return false;
   }

   options->sourcePath = argv[++index];
   continue;
  }

  if(AreStringsEqual(argv[index], L"--target"))
  {
   if(!HasNextArgument(index, argc))
   {
    return false;
   }

   options->targetPath = argv[++index];
   continue;
  }

  if(AreStringsEqual(argv[index], L"--timeout-ms"))
  {
   if(!HasNextArgument(index, argc))
   {
    return false;
   }

   options->timeoutMs = ParseDword(argv[++index], DefaultTimeoutMs);
   continue;
  }

  if(AreStringsEqual(argv[index], L"--retry-ms"))
  {
   if(!HasNextArgument(index, argc))
   {
    return false;
   }

   options->retryDelayMs = ParseDword(argv[++index], DefaultRetryDelayMs);
   continue;
  }

  if(AreStringsEqual(argv[index], L"--restart"))
  {
   options->shouldRestart = true;
   continue;
  }

  if(AreStringsEqual(argv[index], L"--keep-backup"))
  {
   options->keepBackup = true;
   continue;
  }

  fwprintf(stderr, L"Unknown argument: %s\n", argv[index]);
  return false;
 }

 if(options->parentPid == 0 ||
    options->sourcePath == NULL ||
    options->targetPath == NULL)
 {
  return false;
 }

 if(options->retryDelayMs == 0)
 {
  options->retryDelayMs = DefaultRetryDelayMs;
 }

 if(options->timeoutMs == 0)
 {
  options->timeoutMs = DefaultTimeoutMs;
 }

 return true;
}

int wmain(int argc, wchar_t **argv)
{
 UpdaterOptions options;

 if(!ParseArguments(argc, argv, &options))
 {
  PrintUsage();
  return 2;
 }

 if(!DoesFileExist(options.sourcePath))
 {
  fwprintf(stderr, L"Source file does not exist: %s\n", options.sourcePath);
  return 3;
 }

 WaitForParentProcess(options.parentPid);

 if(!ReplaceWithRetry(&options))
 {
  return 4;
 }

 if(options.shouldRestart)
 {
  if(!RestartTarget(options.targetPath))
  {
   return 5;
  }
 }

 return 0;
}
