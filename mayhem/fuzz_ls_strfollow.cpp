#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "cstring_utils.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string a = provider.ConsumeRandomLengthString(1000);
    std::string b = provider.ConsumeRandomLengthString(1000);
    const char* str = a.c_str();
    const char* prefix = b.c_str();

    ls_strfollow(str, prefix);

    return 0;
}