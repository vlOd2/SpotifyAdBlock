#include "dllmain.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            CreateThread(NULL, NULL, AttachHooks, NULL, NULL, NULL);
            break;
        case DLL_PROCESS_DETACH:
            CreateThread(NULL, NULL, DetachHooks, NULL, NULL, NULL);
            break;
    }

    return TRUE;
}

void CreateConsole() 
{
    AllocConsole();

    FILE* fDummy;
    freopen_s(&fDummy, "CONIN$", "r", stdin);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);
    freopen_s(&fDummy, "CONOUT$", "w", stdout);

    HANDLE hConOut = CreateFile(_T("CONOUT$"), GENERIC_READ | GENERIC_WRITE, 
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    SetStdHandle(STD_OUTPUT_HANDLE, hConOut);
}

bool RegexMatch(PCSTR str, PCSTR patern) 
{
    return std::regex_match(str, std::regex(patern));
}

int WINAPI new_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName,
    const ADDRINFOA* pHints, PADDRINFOA* ppResult)
{
    if (RegexMatch(pNodeName, "spclient\.wg\.spotify\.com")) 
    {
        std::cout << "Blocked resolvation of " << pNodeName << "\n";
        return org_getaddrinfo("localhost", pServiceName, pHints, ppResult);
    }

    std::cout << "Resolving address " << pNodeName << "...\n";
    return org_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
}

cef_urlrequest_t* new_cef_urlrequest_create(struct _cef_request_t* request, 
    struct _cef_urlrequest_client_t* client, struct _cef_request_context_t* request_context)
{
    std::cout << "CEF URLREQUEST CREATE CALLED...\n";
    return nullptr;
}

DWORD WINAPI AttachHooks(LPVOID lpParam)
{
    if (GetConsoleWindow() == NULL)
    {
        CreateConsole();
    }

    MH_STATUS initStatus = MH_Initialize();
    if (initStatus != MH_OK)
    {
        char buffer[MAX_PATH];
        std::snprintf(buffer, sizeof(buffer), "SpotifyAdBlock was unable to initialize: %s", 
            MH_StatusToString(initStatus));
        std::cout << buffer << "\n";
        return 0;
    }

    MH_STATUS getaddrinfoHook = MH_CreateHook(&getaddrinfo, &new_getaddrinfo, (LPVOID*)&org_getaddrinfo);
    MH_STATUS cefurlrequestcreateHook = MH_CreateHook(&cef_urlrequest_create, 
        &new_cef_urlrequest_create, (LPVOID*)&org_cef_urlrequest_create);

    if (getaddrinfoHook == MH_OK && cefurlrequestcreateHook == MH_OK)
    {
        std::cout << "SpotifyAdBlock successfully created attachments!" << "\n";
    }
    else 
    {
        char buffer[MAX_PATH];
        std::snprintf(buffer, sizeof(buffer), "SpotifyAdBlock was unable to create attachments: %s, %s",
            MH_StatusToString(getaddrinfoHook), MH_StatusToString(cefurlrequestcreateHook));
        std::cout << buffer << "\n";
    }

    MH_STATUS enableStatus = MH_EnableHook(MH_ALL_HOOKS);
    if (enableStatus == MH_OK)
    {
        std::cout << "SpotifyAdBlock successfully enabled all attachments!\n";
    }
    else
    {
        char buffer[MAX_PATH];
        std::snprintf(buffer, sizeof(buffer), "SpotifyAdBlock was unable to enable all attachments: %s",
            MH_StatusToString(enableStatus));
        std::cout << buffer << "\n";
    }

    return 0;
}

DWORD WINAPI DetachHooks(LPVOID lpParam)
{
    MH_STATUS disableStatus = MH_DisableHook(MH_ALL_HOOKS);
    if (disableStatus == MH_OK)
    {
        std::cout << "SpotifyAdBlock successfully disabled all attachments!\n";
    }
    else
    {
        char buffer[MAX_PATH];
        std::snprintf(buffer, sizeof(buffer), "SpotifyAdBlock was unable to enable all attachments: %s",
            MH_StatusToString(disableStatus));
        std::cout << buffer << "\n";
    }

    MH_STATUS uninitStatus = MH_Uninitialize();
    if (uninitStatus != MH_OK)
    {
        char buffer[MAX_PATH];
        std::snprintf(buffer, sizeof(buffer), "SpotifyAdBlock was unable to uninitialize: %s",
            MH_StatusToString(uninitStatus));
        std::cout << buffer << "\n";
    }

    return 0;
}