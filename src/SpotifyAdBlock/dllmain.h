#pragma once

#define WIN32_LEAN_AND_MEAN
#include <iostream>
#include <string>
#include <regex>
#include <windows.h>
#include <tchar.h>
#include <WS2tcpip.h>
#include <MinHook.h>
#include <include/capi/cef_urlrequest_capi.h>

#pragma comment(lib, "MinHook.lib")
#pragma comment(lib, "libcef.lib")
#pragma comment(lib, "ws2_32.lib")

typedef int (WINAPI* GETADDRINFO)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef cef_urlrequest_t* (CEF_EXPORT* CEFURLREQUESTCREATE)(struct _cef_request_t*, struct _cef_urlrequest_client_t*, struct _cef_request_context_t*);
GETADDRINFO org_getaddrinfo;
CEFURLREQUESTCREATE org_cef_urlrequest_create;

bool RegexMatch(PCSTR str, PCSTR patern);
cef_urlrequest_t* new_cef_urlrequest_create(struct _cef_request_t* request, 
	struct _cef_urlrequest_client_t* client, struct _cef_request_context_t* request_context);
int WINAPI new_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult);
DWORD WINAPI AttachHooks(LPVOID lpParam);
DWORD WINAPI DetachHooks(LPVOID lpParam);