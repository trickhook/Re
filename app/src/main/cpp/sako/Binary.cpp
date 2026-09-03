#include "Binary.h"
#include <cstdio>
#include <cstring>

namespace sako {

Binary loadBinaryFile(const std::string& path, size_t maxBytes) {
    Binary b;
    b.path = path;
    // file name = last path component
    size_t slash = path.find_last_of('/');
    b.name = (slash == std::string::npos) ? path : path.substr(slash + 1);

    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return b;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return b; }
    b.fullSize = u64(sz);

    size_t toRead = size_t(sz);
    if (toRead > maxBytes) { toRead = maxBytes; b.truncated = true; }
    b.data.resize(toRead);
    size_t got = toRead ? fread(b.data.data(), 1, toRead, f) : 0;
    b.data.resize(got);
    fclose(f);
    return b;
}

} // namespace sako
