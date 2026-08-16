#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

static std::string g_script_dir;
static std::string g_build_dir;
static std::string g_ndk_root;
static std::string g_ndk_bin;
static std::string g_acode_dir;
static std::string g_apk_output_dir;

static std::string join_path(const std::string &left, const std::string &right) {
    if (left.empty()) return right;
    if (right.empty()) return left;
    const char last = left.back();
    if (last == '\\' || last == '/') return left + right;
    return left + "\\" + right;
}

static std::string trim_trailing_separators(std::string path) {
    while (path.size() > 3 && (path.back() == '\\' || path.back() == '/')) {
        path.pop_back();
    }
    return path;
}

static std::string quote(const std::string &value) {
    return "\"" + value + "\"";
}

static std::string get_env(const char *name) {
    const DWORD needed = GetEnvironmentVariableA(name, NULL, 0);
    if (needed == 0) return "";

    std::vector<char> buffer(needed);
    const DWORD written = GetEnvironmentVariableA(name, buffer.data(), needed);
    if (written == 0 || written >= needed) return "";
    return std::string(buffer.data(), written);
}

static bool file_exists(const std::string &path) {
    const DWORD attr = GetFileAttributesA(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

static bool dir_exists(const std::string &path) {
    const DWORD attr = GetFileAttributesA(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

static bool dir_create(const std::string &path) {
    if (dir_exists(path)) return true;
    if (CreateDirectoryA(path.c_str(), NULL)) return true;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

static bool copy_file(const std::string &src, const std::string &dst) {
    if (CopyFileA(src.c_str(), dst.c_str(), FALSE)) return true;
    printf("[ERROR] Copy failed: %s -> %s (Win32 error %lu)\n",
           src.c_str(), dst.c_str(), static_cast<unsigned long>(GetLastError()));
    return false;
}

static void append_unique(std::vector<std::string> &items, const std::string &value) {
    if (value.empty()) return;
    const std::string normalized = trim_trailing_separators(value);
    if (std::find(items.begin(), items.end(), normalized) == items.end()) {
        items.push_back(normalized);
    }
}

static std::string ndk_bin_for_root(const std::string &root) {
    return join_path(root, "toolchains\\llvm\\prebuilt\\windows-x86_64\\bin");
}

static bool is_ndk_root(const std::string &root) {
    if (root.empty()) return false;
    return file_exists(join_path(root, "source.properties")) &&
           dir_exists(ndk_bin_for_root(root));
}

static std::string read_ndk_revision(const std::string &root) {
    std::ifstream input(join_path(root, "source.properties"));
    std::string line;
    while (std::getline(input, line)) {
        const std::string key = "Pkg.Revision";
        if (line.compare(0, key.size(), key) != 0) continue;
        const std::size_t equal = line.find('=');
        if (equal == std::string::npos) break;
        std::string revision = line.substr(equal + 1);
        const std::size_t first = revision.find_first_not_of(" \t\r\n");
        const std::size_t last = revision.find_last_not_of(" \t\r\n");
        if (first == std::string::npos) return "unknown";
        return revision.substr(first, last - first + 1);
    }
    return "unknown";
}

static std::string find_side_by_side_ndk(const std::string &sdk_root) {
    if (sdk_root.empty()) return "";

    const std::string ndk_parent = join_path(sdk_root, "ndk");
    if (dir_exists(ndk_parent)) {
        WIN32_FIND_DATAA data = {};
        const std::string pattern = join_path(ndk_parent, "*");
        HANDLE handle = FindFirstFileA(pattern.c_str(), &data);
        if (handle != INVALID_HANDLE_VALUE) {
            std::vector<std::string> versions;
            do {
                if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                const std::string name(data.cFileName);
                if (name == "." || name == "..") continue;
                versions.push_back(name);
            } while (FindNextFileA(handle, &data));
            FindClose(handle);

            std::sort(versions.begin(), versions.end(), std::greater<std::string>());
            for (const std::string &version : versions) {
                const std::string candidate = join_path(ndk_parent, version);
                if (is_ndk_root(candidate)) return candidate;
            }
        }
    }

    const std::string bundle = join_path(sdk_root, "ndk-bundle");
    return is_ndk_root(bundle) ? bundle : "";
}

static std::string resolve_ndk(const std::string &explicit_root) {
    std::vector<std::string> candidates;
    append_unique(candidates, explicit_root);
    append_unique(candidates, get_env("ALLVM_NDK"));
    append_unique(candidates, get_env("ANDROID_NDK_HOME"));
    append_unique(candidates, get_env("ANDROID_NDK_ROOT"));

    append_unique(candidates, find_side_by_side_ndk(get_env("ANDROID_SDK_ROOT")));
    append_unique(candidates, find_side_by_side_ndk(get_env("ANDROID_HOME")));

    const std::string local_app_data = get_env("LOCALAPPDATA");
    if (!local_app_data.empty()) {
        append_unique(
            candidates,
            find_side_by_side_ndk(join_path(local_app_data, "Android\\Sdk")));
    }

    append_unique(candidates, join_path(g_script_dir, "android-ndk-r30-beta1-windows"));

    for (const std::string &candidate : candidates) {
        if (is_ndk_root(candidate)) return candidate;
    }
    return "";
}

static bool init_paths(const std::string &explicit_ndk) {
    char buffer[MAX_PATH] = {};
    const DWORD length = GetModuleFileNameA(NULL, buffer, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        printf("[ERROR] Unable to determine executable path (Win32 error %lu)\n",
               static_cast<unsigned long>(GetLastError()));
        return false;
    }

    const std::string exe_path(buffer, length);
    const std::size_t pos = exe_path.find_last_of("\\/");
    if (pos == std::string::npos) {
        printf("[ERROR] Invalid executable path: %s\n", exe_path.c_str());
        return false;
    }

    g_script_dir = exe_path.substr(0, pos);
    g_build_dir = join_path(g_script_dir, "build-windows");
    g_acode_dir = join_path(g_script_dir, "apkUI");
    g_apk_output_dir = join_path(g_build_dir, "bin");
    g_ndk_root = resolve_ndk(explicit_ndk);
    g_ndk_bin = g_ndk_root.empty() ? "" : ndk_bin_for_root(g_ndk_root);
    return true;
}

static std::string find_vs() {
    const std::string configured = get_env("VSINSTALLDIR");
    if (!configured.empty()) {
        const std::string vcvars = join_path(
            trim_trailing_separators(configured),
            "VC\\Auxiliary\\Build\\vcvars64.bat");
        if (file_exists(vcvars)) return vcvars;
    }

    const char *editions[] = {
        "Enterprise",
        "Professional",
        "Community",
        "BuildTools",
    };
    for (const char *edition : editions) {
        const std::string candidate =
            std::string("C:\\Program Files\\Microsoft Visual Studio\\2022\\") +
            edition + "\\VC\\Auxiliary\\Build\\vcvars64.bat";
        if (file_exists(candidate)) return candidate;
    }

    const std::string program_files_x86 = get_env("ProgramFiles(x86)");
    const std::string vswhere = join_path(
        program_files_x86,
        "Microsoft Visual Studio\\Installer\\vswhere.exe");
    if (!file_exists(vswhere)) return "";

    dir_create(g_build_dir);
    const std::string output_file = join_path(g_build_dir, "vswhere-output.txt");
    const std::string command =
        quote(vswhere) +
        " -latest -products * -requires "
        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64 "
        "-property installationPath > " + quote(output_file);
    const int result = system(command.c_str());
    if (result != 0 || !file_exists(output_file)) return "";

    std::ifstream input(output_file);
    std::string installation;
    std::getline(input, installation);
    input.close();
    DeleteFileA(output_file.c_str());

    if (installation.empty()) return "";
    const std::string vcvars = join_path(
        trim_trailing_separators(installation),
        "VC\\Auxiliary\\Build\\vcvars64.bat");
    return file_exists(vcvars) ? vcvars : "";
}

static std::string temporary_batch_path(const std::string &cwd) {
    const std::string base = cwd.empty() ? g_build_dir : cwd;
    dir_create(base);
    char name[64] = {};
    std::snprintf(
        name,
        sizeof(name),
        "allvm-build-%lu.bat",
        static_cast<unsigned long>(GetCurrentProcessId()));
    return join_path(base, name);
}

static int run_cmd(const std::string &cmd, const std::string &cwd = "") {
    const std::string bat_file = temporary_batch_path(cwd);
    FILE *file = std::fopen(bat_file.c_str(), "wb");
    if (!file) return -1;

    std::fprintf(file, "@echo off\r\n");
    if (!cwd.empty()) std::fprintf(file, "cd /d \"%s\"\r\n", cwd.c_str());
    std::fprintf(file, "%s\r\n", cmd.c_str());
    std::fprintf(file, "exit /b %%ERRORLEVEL%%\r\n");
    std::fclose(file);

    const int result = system(quote(bat_file).c_str());
    DeleteFileA(bat_file.c_str());
    return result;
}

static int run_cmd_vcvars(
    const std::string &vcvars,
    const std::string &cmd,
    const std::string &cwd = "") {
    const std::string bat_file = temporary_batch_path(cwd);
    FILE *file = std::fopen(bat_file.c_str(), "wb");
    if (!file) return -1;

    std::fprintf(file, "@echo off\r\n");
    std::fprintf(file, "call \"%s\" >nul 2>&1\r\n", vcvars.c_str());
    if (!cwd.empty()) std::fprintf(file, "cd /d \"%s\"\r\n", cwd.c_str());
    std::fprintf(file, "%s\r\n", cmd.c_str());
    std::fprintf(file, "exit /b %%ERRORLEVEL%%\r\n");
    std::fclose(file);

    const int result = system(quote(bat_file).c_str());
    DeleteFileA(bat_file.c_str());
    return result;
}

static bool is_safe_target_triple(const std::string &value) {
    if (value.empty()) return false;
    for (const unsigned char c : value) {
        const bool allowed =
            (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.';
        if (!allowed) return false;
    }
    return true;
}

static bool compile_interpreter(const std::string &target_triple) {
    printf("\n============================================================\n");
    printf("Compiling aVMPInterpreter (no obfuscation)...\n");
    printf("Target: %s\n", target_triple.c_str());
    printf("============================================================\n");

    if (!is_safe_target_triple(target_triple)) {
        printf("[ERROR] Invalid target triple: %s\n", target_triple.c_str());
        return false;
    }

    const std::string interp_dir = join_path(g_script_dir, "aVMPInterpreter");
    const std::string bc_file = join_path(interp_dir, "aVMPInterpreter.bc");
    const std::string src_file = join_path(interp_dir, "aVMPInterpreter.c");

    const std::string ndk_clang = g_ndk_bin.empty()
        ? ""
        : join_path(g_ndk_bin, "clang.exe");
    const std::string build_clang = join_path(g_build_dir, "bin\\clang.exe");
    std::string clang_path;

    if (!ndk_clang.empty() && file_exists(ndk_clang)) {
        clang_path = ndk_clang;
        printf("[INFO] Using NDK clang: %s\n", clang_path.c_str());
    } else if (file_exists(build_clang)) {
        clang_path = build_clang;
        printf("[INFO] Using existing ALLVM clang: %s\n", clang_path.c_str());
    } else {
        printf("[ERROR] clang not found. Pass --ndk, set ALLVM_NDK, or build clang first.\n");
        return false;
    }

    const std::string cmd =
        quote(clang_path) + " -O2 -emit-llvm -c " + quote(src_file) +
        " -o " + quote(bc_file) + " -target " + target_triple;
    printf("Running: %s\n", cmd.c_str());

    const int result = run_cmd(cmd);
    if (result != 0) {
        printf("[ERROR] Interpreter compilation failed with code %d\n", result);
        return false;
    }
    printf("[SUCCESS] Interpreter compilation completed.\n");
    return true;
}

static bool generate_vm_h() {
    printf("\n============================================================\n");
    printf("Generating vm.h...\n");
    printf("============================================================\n");

    const std::string bc_file =
        join_path(g_script_dir, "aVMPInterpreter\\aVMPInterpreter.bc");
    const std::string vm_h = join_path(
        g_script_dir,
        "llvm\\include\\llvm\\Transforms\\Obfuscation\\vm.h");

    if (!file_exists(bc_file)) {
        printf("[ERROR] %s not found\n", bc_file.c_str());
        return false;
    }

    std::ifstream input(bc_file, std::ios::binary);
    std::vector<unsigned char> data(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());
    input.close();

    FILE *file = std::fopen(vm_h.c_str(), "wb");
    if (!file) {
        printf("[ERROR] Cannot write %s\n", vm_h.c_str());
        return false;
    }

    std::fprintf(file, "#include <string>\n");
    std::fprintf(file, "#include <vector>\n\n");
    std::fprintf(file, "static const int binary_ir_length = %zu;\n", data.size());
    std::fprintf(file, "static const char binary_ir_data[] =\n");

    for (std::size_t i = 0; i < data.size(); ++i) {
        if (i % 16 == 0) std::fprintf(file, "\"");
        std::fprintf(file, "\\x%02x", static_cast<unsigned int>(data[i]));
        if (i % 16 == 15) std::fprintf(file, "\"\n");
    }
    if (data.size() % 16 != 0) std::fprintf(file, "\"");
    std::fprintf(file, ";\n\n");
    std::fprintf(file, "static std::vector<char> get_binary_ir() {\n");
    std::fprintf(
        file,
        "    return std::vector<char>(binary_ir_data, binary_ir_data + binary_ir_length);\n");
    std::fprintf(file, "}\n");
    std::fclose(file);

    printf("[SUCCESS] Generated vm.h with binary_ir_length = %zu\n", data.size());
    return true;
}

static bool cmake_configure() {
    printf("\n============================================================\n");
    printf("CMake Configure (Windows)\n");
    printf("Build Dir: %s\n", g_build_dir.c_str());
    printf("============================================================\n");

    dir_create(g_build_dir);
    const std::string vcvars = find_vs();
    if (vcvars.empty()) {
        printf("[ERROR] Visual Studio 2022 C++ tools not found.\n");
        return false;
    }
    printf("[INFO] Using Visual Studio environment: %s\n", vcvars.c_str());

    const std::string cmake_cmd =
        "cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS=/utf-8 "
        "-DLLVM_ENABLE_RTTI=ON -DLLVM_ENABLE_EH=ON "
        "-DLLVM_ENABLE_PROJECTS=\"llvm;clang;lld\" "
        "-DLLVM_TARGETS_TO_BUILD=\"AArch64;ARM;X86\" ../llvm";

    printf("[INFO] Running CMake configure...\n%s\n", cmake_cmd.c_str());
    const int result = run_cmd_vcvars(vcvars, cmake_cmd, g_build_dir);
    if (result != 0) {
        printf("[ERROR] CMake configure failed with code %d\n", result);
        return false;
    }

    printf("[SUCCESS] CMake configure completed.\n");
    return true;
}

static bool build_ollvm(int jobs) {
    printf("\n============================================================\n");
    printf("OLLVM Build (Ninja)\n");
    printf("Build Dir: %s\n", g_build_dir.c_str());
    printf("Jobs: %d\n", jobs);
    printf("============================================================\n");

    if (!dir_exists(g_build_dir)) {
        printf("[ERROR] Build directory not found.\n");
        return false;
    }

    const std::string vcvars = find_vs();
    if (vcvars.empty()) {
        printf("[ERROR] Visual Studio 2022 C++ tools not found.\n");
        return false;
    }

    char jobs_buffer[32] = {};
    std::snprintf(jobs_buffer, sizeof(jobs_buffer), "%d", jobs);
    const std::string ninja_cmd =
        std::string("ninja -j") + jobs_buffer +
        " clang llvm-strip llvm-objcopy ollvm-ui";

    printf("[INFO] Building with %s...\n", ninja_cmd.c_str());
    const int result = run_cmd_vcvars(vcvars, ninja_cmd, g_build_dir);
    if (result != 0) {
        printf("[ERROR] Build failed with code %d\n", result);
        return false;
    }

    printf("[SUCCESS] Build completed.\n");
    return true;
}

static bool install_into_ndk() {
    printf("\n============================================================\n");
    printf("Explicit installation into dedicated NDK copy\n");
    printf("============================================================\n");

    if (g_ndk_bin.empty() || !dir_exists(g_ndk_bin)) {
        printf("[ERROR] NDK toolchain bin directory was not found.\n");
        return false;
    }

    printf("[WARNING] This operation modifies: %s\n", g_ndk_root.c_str());
    printf("[WARNING] Use only a dedicated NDK copy. Original files receive .bak backups.\n");

    const std::string build_bin = join_path(g_build_dir, "bin");
    const char *files[] = {
        "clang.exe",
        "clang++.exe",
        "clang-cl.exe",
        "clang-cpp.exe",
        "llvm-strip.exe",
        "llvm-objcopy.exe",
    };

    for (const char *name : files) {
        const std::string src = join_path(build_bin, name);
        const std::string dst = join_path(g_ndk_bin, name);
        if (!file_exists(src)) {
            printf("[SKIP] %s was not produced by the build.\n", name);
            continue;
        }

        const std::string backup = dst + ".bak";
        if (!file_exists(backup) && file_exists(dst)) {
            printf("[INFO] Backing up %s...\n", name);
            if (!copy_file(dst, backup)) return false;
        }

        if (!copy_file(src, dst)) return false;
        printf("[OK] %s\n", name);
    }

    printf("[SUCCESS] ALLVM tools installed into the dedicated NDK copy.\n");
    return true;
}

static bool run_doctor() {
    const std::string doctor = join_path(g_script_dir, "tools\\allvm-doctor.py");
    if (!file_exists(doctor)) {
        printf("[ERROR] Environment doctor not found: %s\n", doctor.c_str());
        return false;
    }

    std::string arguments = quote(doctor);
    if (!g_ndk_root.empty()) arguments += " --ndk " + quote(g_ndk_root);

    int result = run_cmd("py -3 " + arguments, g_script_dir);
    if (result != 0) {
        result = run_cmd("python " + arguments, g_script_dir);
    }
    return result == 0;
}

static bool build_apk() {
    printf("\n============================================================\n");
    printf("Building Acode APK with Cordova...\n");
    printf("Acode Dir: %s\n", g_acode_dir.c_str());
    printf("Output Dir: %s\n", g_apk_output_dir.c_str());
    printf("============================================================\n");

    if (!dir_exists(g_acode_dir)) {
        printf("[ERROR] Acode directory not found at %s\n", g_acode_dir.c_str());
        return false;
    }

    dir_create(g_build_dir);
    dir_create(g_apk_output_dir);

    const std::string platforms_dir = join_path(g_acode_dir, "platforms");
    if (!dir_exists(platforms_dir)) {
        printf("[0/3] Adding Cordova Android platform...\n");
        const int result = run_cmd("npx cordova platform add android", g_acode_dir);
        if (result != 0) {
            printf("[WARN] Platform add failed with code %d; continuing.\n", result);
        }
    }

    printf("[1/2] Building web assets...\n");
    int result = run_cmd("npm run build", g_acode_dir);
    if (result != 0) {
        printf("[ERROR] Web asset build failed with code %d\n", result);
        return false;
    }

    printf("[2/2] Building Android APK...\n");
    result = run_cmd("npx cordova build android", g_acode_dir);
    if (result != 0) {
        printf("[ERROR] Cordova build failed with code %d\n", result);
        return false;
    }

    const std::string apk_src = join_path(
        g_acode_dir,
        "platforms\\android\\app\\build\\outputs\\apk\\debug\\app-debug.apk");
    const std::string apk_dst = join_path(g_apk_output_dir, "Acode-OLLVM.apk");

    if (file_exists(apk_src)) {
        if (!copy_file(apk_src, apk_dst)) return false;
        printf("[SUCCESS] APK copied to: %s\n", apk_dst.c_str());
    } else {
        printf("[WARN] APK not found at the expected location.\n");
    }
    return true;
}

static bool build_apk_release() {
    printf("\n============================================================\n");
    printf("Building Acode Release APK...\n");
    printf("============================================================\n");

    if (!dir_exists(g_acode_dir)) {
        printf("[ERROR] Acode directory not found at %s\n", g_acode_dir.c_str());
        return false;
    }

    dir_create(g_build_dir);
    dir_create(g_apk_output_dir);

    printf("[1/2] Building web assets...\n");
    int result = run_cmd("npm run build", g_acode_dir);
    if (result != 0) {
        printf("[ERROR] Web asset build failed with code %d\n", result);
        return false;
    }

    printf("[2/2] Building release APK...\n");
    result = run_cmd("npx cordova build android --release", g_acode_dir);
    if (result != 0) {
        printf("[ERROR] Cordova release build failed with code %d\n", result);
        return false;
    }

    const std::string apk_src = join_path(
        g_acode_dir,
        "platforms\\android\\app\\build\\outputs\\apk\\release\\app-release-unsigned.apk");
    const std::string apk_dst =
        join_path(g_apk_output_dir, "Acode-OLLVM-release-unsigned.apk");

    if (file_exists(apk_src)) {
        if (!copy_file(apk_src, apk_dst)) return false;
        printf("[SUCCESS] Release APK copied to: %s\n", apk_dst.c_str());
    } else {
        printf("[WARN] Release APK not found at the expected location.\n");
    }
    return true;
}

static void print_usage(const char *program) {
    printf("Usage: %s [options]\n\n", program);
    printf("Build options:\n");
    printf("  --ndk <path>             Android NDK root directory\n");
    printf("  --target <triple>        Interpreter target triple\n");
    printf("  -j <jobs>                Ninja parallel job count\n");
    printf("  --skip-build             Reuse existing generated/build outputs\n");
    printf("  --install-into-ndk       Explicitly modify a dedicated NDK copy\n");
    printf("  --doctor                 Run environment diagnostics before building\n");
    printf("  --doctor-only            Run diagnostics and exit\n");
    printf("  --apk                    Build debug APK after toolchain build\n");
    printf("  --apk-release            Build release APK after toolchain build\n");
    printf("  --all                    Alias for --apk\n");
    printf("  -h, --help               Show this help\n\n");
    printf("NDK discovery order:\n");
    printf("  --ndk, ALLVM_NDK, ANDROID_NDK_HOME, ANDROID_NDK_ROOT,\n");
    printf("  Android SDK side-by-side NDK, repository-local legacy NDK.\n");
}

int main(int argc, char *argv[]) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
    }

    std::string explicit_ndk;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--ndk" && i + 1 < argc) {
            explicit_ndk = argv[i + 1];
            break;
        }
    }

    if (!init_paths(explicit_ndk)) return 1;

    std::string target_triple = "x86_64-pc-windows-msvc";
    bool skip_build = false;
    bool build_apk_flag = false;
    bool build_apk_release_flag = false;
    bool install_into_ndk_flag = false;
    bool doctor_before_build = false;
    bool doctor_only = false;

    unsigned int detected_jobs = std::thread::hardware_concurrency();
    int jobs = detected_jobs == 0 ? 8 : static_cast<int>(detected_jobs);

    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (arg == "--ndk" && i + 1 < argc) {
            ++i;
        } else if (arg == "--target" && i + 1 < argc) {
            target_triple = argv[++i];
        } else if (arg == "--skip-build") {
            skip_build = true;
        } else if (arg == "-j" && i + 1 < argc) {
            char *end = NULL;
            const long parsed = std::strtol(argv[++i], &end, 10);
            if (!end || *end != '\0' || parsed <= 0 || parsed > 1024) {
                printf("[ERROR] Invalid job count. Expected 1..1024.\n");
                return 2;
            }
            jobs = static_cast<int>(parsed);
        } else if (arg == "--install-into-ndk") {
            install_into_ndk_flag = true;
        } else if (arg == "--doctor") {
            doctor_before_build = true;
        } else if (arg == "--doctor-only") {
            doctor_only = true;
        } else if (arg == "--apk") {
            build_apk_flag = true;
        } else if (arg == "--apk-release") {
            build_apk_release_flag = true;
        } else if (arg == "--all") {
            build_apk_flag = true;
        } else {
            printf("[ERROR] Unknown or incomplete option: %s\n", arg.c_str());
            print_usage(argv[0]);
            return 2;
        }
    }

    printf("============================================================\n");
    printf("ALLVM Build Helper\n");
    printf("Repository: %s\n", g_script_dir.c_str());
    printf("Build dir: %s\n", g_build_dir.c_str());
    if (g_ndk_root.empty()) {
        printf("NDK: not found\n");
    } else {
        printf("NDK: %s\n", g_ndk_root.c_str());
        printf("NDK revision: %s\n", read_ndk_revision(g_ndk_root).c_str());
    }
    printf("============================================================\n");

    if (doctor_only) return run_doctor() ? 0 : 1;
    if (doctor_before_build && !run_doctor()) {
        printf("[ERROR] Environment diagnostics failed.\n");
        return 1;
    }

    if (!skip_build && g_ndk_root.empty()) {
        printf("[ERROR] Android NDK not found. Use --ndk or set ALLVM_NDK.\n");
        return 1;
    }

    if (!skip_build) {
        if (!cmake_configure()) return 1;
        if (!compile_interpreter(target_triple)) return 1;
    }

    if (!generate_vm_h()) return 1;

    if (!skip_build) {
        if (!build_ollvm(jobs)) return 1;
        if (install_into_ndk_flag) {
            if (!install_into_ndk()) return 1;
        } else {
            printf("\n[SAFE DEFAULT] Original NDK was not modified.\n");
            printf("Built tools are in: %s\n", join_path(g_build_dir, "bin").c_str());
            printf("Use --install-into-ndk only with a dedicated NDK copy.\n");
        }
    }

    if ((build_apk_flag || build_apk_release_flag) && !install_into_ndk_flag) {
        printf("[WARN] APK build was requested without --install-into-ndk.\n");
        printf("[WARN] Ensure Cordova is explicitly configured to use the ALLVM compiler.\n");
    }

    if (build_apk_release_flag) {
        if (!build_apk_release()) return 1;
    } else if (build_apk_flag) {
        if (!build_apk()) return 1;
    }

    printf("\n============================================================\n");
    printf("All requested steps completed successfully.\n");
    printf("============================================================\n");
    return 0;
}
