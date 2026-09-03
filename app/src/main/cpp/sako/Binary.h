// File loading + format detection
#pragma once
#include "Types.h"

namespace sako {

// Loads a file into memory. Files larger than maxBytes are truncated
// (truncated=true, fullSize=real size).
Binary loadBinaryFile(const std::string& path, size_t maxBytes = size_t(256) * 1024 * 1024);

} // namespace sako
