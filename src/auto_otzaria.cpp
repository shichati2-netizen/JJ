#include "common.hpp"

int wmain() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    const std::wstring target = L"E:\\OTZARIA\\OTZARIA.EXE";
    constexpr unsigned long long expectedSize = 4783616ULL;
    const std::wstring expectedVersion = L"0.9.98.32466";

    unsigned long long actualSize = 0;
    if (!ae::fileSize(target, actualSize)) {
        std::wcout << L"NOT_FOUND: E:\\OTZARIA\\OTZARIA.EXE was not found.\n";
        return 2;
    }

    if (actualSize != expectedSize) {
        std::wcout << L"NOT_FOUND: file size is " << actualSize
                   << L" bytes; expected " << expectedSize << L".\n";
        return 3;
    }

    std::wstring version;
    if (!ae::fileVersion(target, version)) {
        std::wcout << L"NOT_FOUND: Windows version information is missing or unreadable.\n";
        return 4;
    }
    if (version != expectedVersion) {
        std::wcout << L"NOT_FOUND: file version is " << version
                   << L"; expected " << expectedVersion << L".\n";
        return 5;
    }

    std::wstring hash;
    if (!ae::sha1File(target, hash)) {
        std::wcout << L"ERROR: could not calculate the file signature.\n";
        return 6;
    }

    // The supplied XML template uses a 40-character hexadecimal SIGNATURE.
    // This tool calculates SHA-1; verify this matches the installed AE version
    // before importing the generated item into a production configuration.
    const std::wstring item = ae::makeItem(target, hash, version, L"אוצריא");
    const std::filesystem::path output =
        std::filesystem::path(ae::exeDirectory()) / L"AE_Otzaria_ITEM.xml";

    if (!ae::writeUtf8(output, L"<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n" + item + L"\r\n")) {
        std::wcout << L"ERROR: could not write AE_Otzaria_ITEM.xml.\n";
        return 7;
    }

    std::wcout << L"SUCCESS: exact file size and version matched.\n";
    std::wcout << L"SHA1: " << hash << L"\n";
    std::wcout << L"ENTRY: " << output.wstring() << L"\n";
    std::wcout << L"NOTE: an XML entry was created; encrypted AEConfig.xml was not modified.\n";
    return 0;
}
