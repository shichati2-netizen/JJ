#pragma once
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <commdlg.h>
#include <winver.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "comdlg32.lib")

namespace ae {

inline std::wstring basename(const std::wstring& p) {
    return std::filesystem::path(p).filename().wstring();
}

inline std::wstring stem(const std::wstring& p) {
    return std::filesystem::path(p).stem().wstring();
}

inline std::wstring exeDirectory() {
    std::wstring buffer(32768, L'\0');
    DWORD n = GetModuleFileNameW(nullptr, buffer.data(), (DWORD)buffer.size());
    if (!n || n >= buffer.size()) return L".";
    buffer.resize(n);
    return std::filesystem::path(buffer).parent_path().wstring();
}

inline std::wstring xmlEscape(const std::wstring& s) {
    std::wstring out;
    for (wchar_t c : s) {
        switch (c) {
        case L'&': out += L"&amp;"; break;
        case L'<': out += L"&lt;"; break;
        case L'>': out += L"&gt;"; break;
        case L'"': out += L"&quot;"; break;
        case L'\'': out += L"&apos;"; break;
        default: out += c; break;
        }
    }
    return out;
}

inline std::string toUtf8(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n, nullptr, nullptr);
    return out;
}

inline bool writeUtf8(const std::filesystem::path& path, const std::wstring& text) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    const unsigned char bom[] = {0xEF, 0xBB, 0xBF};
    f.write(reinterpret_cast<const char*>(bom), sizeof(bom));
    const std::string bytes = toUtf8(text);
    f.write(bytes.data(), (std::streamsize)bytes.size());
    return f.good();
}

inline bool fileSize(const std::wstring& path, unsigned long long& size) {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) return false;
    ULARGE_INTEGER v{};
    v.HighPart = data.nFileSizeHigh;
    v.LowPart = data.nFileSizeLow;
    size = v.QuadPart;
    return true;
}

inline bool fileVersion(const std::wstring& path, std::wstring& version) {
    DWORD ignored = 0;
    DWORD bytes = GetFileVersionInfoSizeW(path.c_str(), &ignored);
    if (!bytes) return false;
    std::vector<BYTE> data(bytes);
    if (!GetFileVersionInfoW(path.c_str(), 0, bytes, data.data())) return false;
    VS_FIXEDFILEINFO* info = nullptr;
    UINT len = 0;
    if (!VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&info), &len) ||
        !info || len < sizeof(VS_FIXEDFILEINFO) || info->dwSignature != 0xFEEF04BD) return false;

    std::wostringstream s;
    s << HIWORD(info->dwFileVersionMS) << L"."
      << LOWORD(info->dwFileVersionMS) << L"."
      << HIWORD(info->dwFileVersionLS) << L"."
      << LOWORD(info->dwFileVersionLS);
    version = s.str();
    return true;
}

inline bool sha1File(const std::wstring& path, std::wstring& hex) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<UCHAR> object, digest;
    HANDLE file = INVALID_HANDLE_VALUE;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr, 0) < 0) goto cleanup;
    {
        DWORD objLen = 0, hashLen = 0, got = 0;
        if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &got, 0) < 0) goto cleanup;
        if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen), &got, 0) < 0) goto cleanup;
        object.resize(objLen);
        digest.resize(hashLen);
    }
    if (BCryptCreateHash(alg, &hash, object.data(), (ULONG)object.size(), nullptr, 0, 0) < 0) goto cleanup;

    file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) goto cleanup;
    {
        std::vector<UCHAR> buffer(1024 * 1024);
        DWORD read = 0;
        while (ReadFile(file, buffer.data(), (DWORD)buffer.size(), &read, nullptr) && read) {
            if (BCryptHashData(hash, buffer.data(), read, 0) < 0) goto cleanup;
        }
        if (GetLastError() != ERROR_HANDLE_EOF && read == 0 && GetLastError() != ERROR_SUCCESS) {
            // ReadFile normally returns FALSE only on a real I/O failure.
            if (GetLastError() != ERROR_HANDLE_EOF) goto cleanup;
        }
    }
    if (BCryptFinishHash(hash, digest.data(), (ULONG)digest.size(), 0) < 0) goto cleanup;
    {
        static const wchar_t* digits = L"0123456789ABCDEF";
        hex.clear();
        for (UCHAR b : digest) {
            hex.push_back(digits[b >> 4]);
            hex.push_back(digits[b & 0x0F]);
        }
    }
    ok = true;

cleanup:
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

inline std::wstring timestampNow() {
    SYSTEMTIME t{};
    GetLocalTime(&t);
    std::wostringstream s;
    s << std::setfill(L'0')
      << std::setw(2) << t.wMonth << L"/"
      << std::setw(2) << t.wDay << L"/"
      << t.wYear << L" "
      << std::setw(2) << t.wHour << L":"
      << std::setw(2) << t.wMinute << L":"
      << std::setw(2) << t.wSecond;
    return s.str();
}

inline std::wstring makeItem(const std::wstring& path,
                             const std::wstring& hash,
                             const std::wstring& version,
                             const std::wstring& productName) {
    const std::wstring fileName = basename(path);
    std::wostringstream x;
    x << L"<ITEM><TRUSTED>0</TRUSTED><SIGNATURE>" << hash
      << L"</SIGNATURE><PATHNAME>" << xmlEscape(path)
      << L"</PATHNAME><DATE>" << timestampNow()
      << L"</DATE><COMMENT></COMMENT><TYPE>File</TYPE><PUBLISHER></PUBLISHER><PRODUCTNAME>"
      << xmlEscape(productName) << L"</PRODUCTNAME><FILENAME>"
      << xmlEscape(fileName) << L"</FILENAME><FILEVERSION>"
      << xmlEscape(version) << L"</FILEVERSION></ITEM>";
    return x.str();
}

inline std::wstring chooseExeFile() {
    wchar_t path[32768]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFile = path;
    ofn.nMaxFile = (DWORD)(sizeof(path) / sizeof(path[0]));
    ofn.lpstrFilter = L"Executable files (*.exe)\0*.exe\0All files (*.*)\0*.*\0\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    ofn.lpstrTitle = L"Choose a file for an Anti-Executable entry";
    if (!GetOpenFileNameW(&ofn)) return {};
    return path;
}

inline std::wstring listType() {
    std::wcout << L"\n1 = WHITELIST (allowed)\n2 = BLACKLIST (blocked)\nChoose 1 or 2: ";
    std::wstring value;
    std::getline(std::wcin, value);
    return value;
}

inline bool saveEntry(const std::wstring& list, const std::wstring& item, const std::wstring& prefix) {
    const std::wstring section = (list == L"2") ? L"BLACKLIST" : L"WHITELIST";
    const std::filesystem::path out = std::filesystem::path(exeDirectory()) / (prefix + L".txt");
    std::wstring content = L"[" + section + L"]\r\n" + item + L"\r\n";
    return writeUtf8(out, content);
}

} // namespace ae
