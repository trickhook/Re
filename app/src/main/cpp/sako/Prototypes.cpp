#include "Prototypes.h"

namespace sako {
namespace proto {

// Only functions whose signature is fixed by a standard or by the NDK. A
// wrong prototype is worse than none: it makes the decompiler assert a
// parameter list that is not there, so anything uncertain is left out.
const KnownProto kKnownProtos[] = {
    // --- strings: the ones that make literals appear -----------------------
    {"strlen",    "z", "s"},
    {"strnlen",   "z", "sz"},
    {"strcmp",    "i", "ss"},
    {"strncmp",   "i", "ssz"},
    {"strcasecmp","i", "ss"},
    {"strncasecmp","i","ssz"},
    {"strcpy",    "s", "ps"},
    {"strncpy",   "s", "psz"},
    {"strcat",    "s", "ps"},
    {"strncat",   "s", "psz"},
    {"strstr",    "s", "ss"},
    {"strchr",    "s", "si"},
    {"strrchr",   "s", "si"},
    {"strdup",    "s", "s"},
    {"strndup",   "s", "sz"},
    {"strtok",    "s", "ps"},
    {"strerror",  "s", "i"},

    // --- memory ------------------------------------------------------------
    {"memcpy",    "p", "ppz"},
    {"memmove",   "p", "ppz"},
    {"memset",    "p", "piz"},
    {"memcmp",    "i", "ppz"},
    {"memchr",    "p", "piz"},
    {"malloc",    "p", "z"},
    {"calloc",    "p", "zz"},
    {"realloc",   "p", "pz"},
    {"free",      "v", "p"},
    {"_Znwm",     "p", "z"},     // operator new(unsigned long)
    {"_Znam",     "p", "z"},     // operator new[](unsigned long)
    {"_ZdlPv",    "v", "p"},     // operator delete(void*)
    {"_ZdaPv",    "v", "p"},     // operator delete[](void*)

    // --- stdio -------------------------------------------------------------
    {"printf",    "i", "s."},
    {"fprintf",   "i", "ps."},
    {"sprintf",   "i", "ps."},
    {"snprintf",  "i", "pzs."},
    {"vsnprintf", "i", "pzsp"},
    {"puts",      "i", "s"},
    {"fputs",     "i", "sp"},
    {"fopen",     "p", "ss"},
    {"fclose",    "i", "p"},
    {"fread",     "z", "pzzp"},
    {"fwrite",    "z", "pzzp"},
    {"fgets",     "s", "pip"},
    {"perror",    "v", "s"},

    // --- stdlib / env ------------------------------------------------------
    {"atoi",      "i", "s"},
    {"atol",      "l", "s"},
    {"atoll",     "l", "s"},
    {"strtol",    "l", "spi"},
    {"strtoul",   "l", "spi"},
    {"strtoll",   "l", "spi"},
    {"strtod",    "d", "sp"},
    {"getenv",    "s", "s"},
    {"setenv",    "i", "ssi"},
    {"system",    "i", "s"},
    {"abort",     "v", ""},
    {"exit",      "v", "i"},
    {"qsort",     "v", "pzzp"},

    // --- files and processes ----------------------------------------------
    {"open",      "i", "si."},
    {"openat",    "i", "isi."},
    {"read",      "l", "ipz"},
    {"write",     "l", "ipz"},
    {"close",     "i", "i"},
    {"lseek",     "l", "ili"},
    {"access",    "i", "si"},
    {"stat",      "i", "sp"},
    {"lstat",     "i", "sp"},
    {"unlink",    "i", "s"},
    {"rename",    "i", "ss"},
    {"mkdir",     "i", "si"},
    {"readlink",  "l", "spz"},
    {"realpath",  "s", "sp"},
    {"opendir",   "p", "s"},
    {"readdir",   "p", "p"},
    {"closedir",  "i", "p"},
    {"mmap",      "p", "pziil"},
    {"munmap",    "i", "pz"},
    {"mprotect",  "i", "pzi"},
    {"getpid",    "i", ""},
    {"getppid",   "i", ""},
    {"gettid",    "i", ""},
    {"kill",      "i", "ii"},
    {"prctl",     "i", "i."},
    {"ptrace",    "l", "illp"},
    {"syscall",   "l", "l."},

    // --- dynamic linking ---------------------------------------------------
    {"dlopen",    "p", "si"},
    {"dlsym",     "p", "ps"},
    {"dlclose",   "i", "p"},
    {"dlerror",   "s", ""},
    {"dladdr",    "i", "pp"},

    // --- threads -----------------------------------------------------------
    {"pthread_create",       "i", "pppp"},
    {"pthread_join",         "i", "lp"},
    {"pthread_detach",       "i", "l"},
    {"pthread_self",         "l", ""},
    {"pthread_mutex_init",   "i", "pp"},
    {"pthread_mutex_lock",   "i", "p"},
    {"pthread_mutex_unlock", "i", "p"},
    {"pthread_mutex_destroy","i", "p"},
    {"pthread_cond_wait",    "i", "pp"},
    {"pthread_cond_signal",  "i", "p"},
    {"pthread_once",         "i", "pp"},
    {"pthread_getspecific",  "p", "u"},
    {"pthread_setspecific",  "i", "up"},

    // --- Android -----------------------------------------------------------
    {"__android_log_print",  "i", "iss."},
    {"__android_log_write",  "i", "iss"},
    {"__android_log_assert", "v", "sss."},
    {"__system_property_get","i", "sp"},
    {"AAssetManager_open",      "p", "psi"},
    {"AAsset_read",             "i", "ppz"},
    {"AAsset_close",            "v", "p"},

    // --- bionic _FORTIFY_SOURCE variants ----------------------------------
    // Android compiles with FORTIFY on by default, so these are what actually
    // appear in the import table; the plain names often do not.
    {"__printf_chk",   "i", "is."},
    {"__fprintf_chk",  "i", "pis."},
    {"__sprintf_chk",  "i", "pizs."},
    {"__snprintf_chk", "i", "pzizs."},
    {"__vsnprintf_chk","i", "pzizsp"},
    {"__strlen_chk",   "z", "sz"},
    {"__strcpy_chk",   "s", "psz"},
    {"__strncpy_chk",  "s", "pszz"},
    {"__strcat_chk",   "s", "psz"},
    {"__memcpy_chk",   "p", "ppzz"},
    {"__memmove_chk",  "p", "ppzz"},
    {"__memset_chk",   "p", "pizz"},
    {"__read_chk",     "l", "ipzz"},

    // --- time --------------------------------------------------------------
    {"time",       "l", "p"},
    {"clock_gettime", "i", "ip"},
    {"gettimeofday",  "i", "pp"},
    {"usleep",     "i", "u"},
    {"sleep",      "u", "u"},
    {"nanosleep",  "i", "pp"},
};

const int kKnownProtoCount = int(sizeof(kKnownProtos) / sizeof(kKnownProtos[0]));

} // namespace proto
} // namespace sako
