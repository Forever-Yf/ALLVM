#!/usr/bin/env python3
"""Apply exact MSVC and skip-build fixes to build.cpp."""

from pathlib import Path


PATH = Path("build.cpp")


def replace_once(text: str, old: str, new: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one match, found {count}: {old[:100]!r}")
    return text.replace(old, new)


def replace_count(text: str, old: str, new: str, expected: int) -> str:
    count = text.count(old)
    if count != expected:
        raise SystemExit(
            f"expected {expected} matches, found {count}: {old[:100]!r}"
        )
    return text.replace(old, new)


def main() -> None:
    text = PATH.read_text(encoding="utf-8")

    text = replace_once(
        text,
        '''static bool dir_create(const std::string &path) {
    if (dir_exists(path)) return true;
    if (CreateDirectoryA(path.c_str(), NULL)) return true;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

static bool copy_file''',
        '''static bool dir_create(const std::string &path) {
    if (dir_exists(path)) return true;
    if (CreateDirectoryA(path.c_str(), NULL)) return true;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

static FILE *open_file(const std::string &path, const char *mode) {
    FILE *file = NULL;
    const int error = fopen_s(&file, path.c_str(), mode);
    return error == 0 ? file : NULL;
}

static bool copy_file''',
    )

    text = replace_count(
        text,
        'FILE *file = std::fopen(bat_file.c_str(), "wb");',
        'FILE *file = open_file(bat_file, "wb");',
        2,
    )
    text = replace_once(
        text,
        'FILE *file = std::fopen(vm_h.c_str(), "wb");',
        'FILE *file = open_file(vm_h, "wb");',
    )

    text = replace_once(
        text,
        'printf("  --skip-build             Reuse existing generated/build outputs\\n");',
        'printf("  --skip-build             Reuse outputs; may combine with explicit install\\n");',
    )

    text = replace_once(
        text,
        '''    if (!skip_build && g_ndk_root.empty()) {
        printf("[ERROR] Android NDK not found. Use --ndk or set ALLVM_NDK.\\n");
        return 1;
    }''',
        '''    if ((!skip_build || install_into_ndk_flag) && g_ndk_root.empty()) {
        printf("[ERROR] Android NDK not found. Use --ndk or set ALLVM_NDK.\\n");
        return 1;
    }''',
    )

    text = replace_once(
        text,
        '''    if (!skip_build) {
        if (!build_ollvm(jobs)) return 1;
        if (install_into_ndk_flag) {
            if (!install_into_ndk()) return 1;
        } else {
            printf("\\n[SAFE DEFAULT] Original NDK was not modified.\\n");
            printf("Built tools are in: %s\\n", join_path(g_build_dir, "bin").c_str());
            printf("Use --install-into-ndk only with a dedicated NDK copy.\\n");
        }
    }''',
        '''    if (!skip_build) {
        if (!build_ollvm(jobs)) return 1;
    }

    if (install_into_ndk_flag) {
        if (!install_into_ndk()) return 1;
    } else {
        printf("\\n[SAFE DEFAULT] Original NDK was not modified.\\n");
        printf("Built tools are in: %s\\n", join_path(g_build_dir, "bin").c_str());
        printf("Use --install-into-ndk only with a dedicated NDK copy.\\n");
    }''',
    )

    if "std::fopen" in text:
        raise SystemExit("std::fopen remains in build.cpp")
    if "fopen_s" not in text:
        raise SystemExit("fopen_s helper was not added")
    if "if (install_into_ndk_flag)" not in text:
        raise SystemExit("explicit installation path is missing")

    PATH.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
