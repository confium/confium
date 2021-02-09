#include <botan/hash.h>
#include <botan/hex.h>
#include <map>
#include <stdint.h>
#include <string>

#define PUBLICAPI __attribute__((visibility("default")))

static uint32_t
ffi_exception(FILE *fp, const char *func, const char *msg, uint32_t ret = 1)
{
    fprintf(fp, "[%s()] Error 0x%08X: %s\n", func, ret, msg);
    return ret;
}

#define FFI_GUARD_FP(fp)                                           \
    catch (std::exception & e)                                     \
    {                                                              \
        return ffi_exception((fp), __func__, e.what());            \
    }                                                              \
    catch (...)                                                    \
    {                                                              \
        return ffi_exception((fp), __func__, "unknown exception"); \
    }

#define FFI_GUARD FFI_GUARD_FP((stderr))

struct Confium;
struct Options;
struct Hash;

extern "C" {
PUBLICAPI uint32_t cfmp_interface_version(Confium *cfm);
PUBLICAPI uint32_t cfmp_initialize(Confium *cfm, const Options *opts);
PUBLICAPI uint32_t cfmp_finalize(Confium *cfm);

PUBLICAPI const uint8_t *cfmp_query_interfaces(Confium *cfm);

PUBLICAPI uint32_t cfmp_hash_create(Confium *   cfm,
                                    Hash **     hash,
                                    const char *name,
                                    Options *   opts);
PUBLICAPI uint32_t cfmp_hash_output_size(Hash *hash, uint32_t *size);
PUBLICAPI uint32_t cfmp_hash_block_size(Hash *hash, uint32_t *size);
PUBLICAPI uint32_t cfmp_hash_update(Hash *hash, const uint8_t *data, uint32_t length);
PUBLICAPI uint32_t cfmp_hash_reset(Hash *hash);
PUBLICAPI uint32_t cfmp_hash_clone(Hash *src, Hash **dst);
PUBLICAPI uint32_t cfmp_hash_finalize(Hash *hash, uint8_t *result, uint32_t length);
PUBLICAPI void     cfmp_hash_destroy(Hash *hash);
}

uint32_t
cfmp_interface_version(Confium *cfm)
{
    return 0;
}

uint32_t
cfmp_initialize(Confium *cfm, const Options *opts)
{
    return 0;
}

uint32_t
cfmp_finalize(Confium *cfm)
{
    return 0;
}

const uint8_t *
cfmp_query_interfaces(Confium *cfm)
{
    static const uint8_t interfaces[] = {
      'h',
      'a',
      's',
      'h',
      '\0',
      0,
      0,
      0,
    };
    return interfaces;
}

uint32_t
cfmp_hash_create(Confium *cfm, Hash **hash, const char *name, Options *opts)
try {
    auto obj = Botan::HashFunction::create(name).release();
    *hash = (Hash *) obj;
    return 0;
}
FFI_GUARD

uint32_t
cfmp_hash_output_size(Hash *hash, uint32_t *size)
try {
    auto obj = (Botan::HashFunction *) hash;
    *size = obj->output_length();
    return 0;
}
FFI_GUARD

uint32_t
cfmp_hash_block_size(Hash *hash, uint32_t *size)
try {
    auto obj = (Botan::HashFunction *) hash;
    *size = obj->hash_block_size();
    return 0;
}
FFI_GUARD

uint32_t
cfmp_hash_update(Hash *hash, const uint8_t *data, uint32_t length)
try {
    auto obj = (Botan::HashFunction *) hash;
    obj->update(data, length);
    return 0;
}
FFI_GUARD

uint32_t
cfmp_hash_reset(Hash *hash)
try {
    auto obj = (Botan::HashFunction *) hash;
    obj->clear();
    return 0;
}
FFI_GUARD

uint32_t
cfmp_hash_clone(Hash *src, Hash **dst)
try {
    auto obj = (Botan::HashFunction *) src;
    *dst = (Hash *) obj->copy_state().release();
    return 0;
}
FFI_GUARD

uint32_t
cfmp_hash_finalize(Hash *hash, uint8_t *result, uint32_t length)
try {
    auto obj = (Botan::HashFunction *) hash;
    if (length < obj->output_length()) {
        return 1;
    }
    std::vector<uint8_t> digest;
    obj->final(digest);
    std::copy(digest.begin(), digest.end(), result);
    return 0;
}
FFI_GUARD

void
cfmp_hash_destroy(Hash *hash)
{
    auto obj = (Botan::HashFunction *) hash;
    delete obj;
}
