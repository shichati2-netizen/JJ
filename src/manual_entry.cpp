#include "common.hpp"

int wmain() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    std::wcout << L"Anti-Executable manual entry builder\n";
    std::wcout << L"Select an EXE file in the file dialog.\n";

    const std::wstring path = ae::chooseExeFile();
    if (path.empty()) {
        std::wcout << L"CANCELLED: no file was selected.\n";
        return 1;
    }

    const std::wstring list = ae::listType();
    if (list != L"1" && list != L"2") {
        std::wcout << L"ERROR: choose 1 or 2.\n";
        return 2;
    }

    std::wstring version;
    if (!ae::fileVersion(path, version)) {
        std::wcout << L"ERROR: the selected file has no readable Windows version resource.\n";
        std::wcout << L"No entry was generated, because guessing the version could create a bad rule.\n";
        return 3;
    }

    std::wstring hash;
    if (!ae::sha1File(path, hash)) {
        std::wcout << L"ERROR: could not calculate the file signature.\n";
        return 4;
    }

    const std::wstring product = ae::stem(path);
    const std::wstring item = ae::makeItem(path, hash, version, product);
    const std::wstring prefix = (list == L"2") ? L"AE_Manual_BLACKLIST_ITEM" : L"AE_Manual_WHITELIST_ITEM";
    if (!ae::saveEntry(list, item, prefix)) {
        std::wcout << L"ERROR: could not write the generated entry file.\n";
        return 5;
    }

    const std::filesystem::path output =
        std::filesystem::path(ae::exeDirectory()) / (prefix + L".txt");
    std::wcout << L"SUCCESS: entry file created.\n";
    std::wcout << L"SHA1: " << hash << L"\n";
    std::wcout << L"FILE VERSION: " << version << L"\n";
    std::wcout << L"ENTRY: " << output.wstring() << L"\n";
    std::wcout << L"NOTE: the encrypted AEConfig.xml was not modified.\n";
    return 0;
}
