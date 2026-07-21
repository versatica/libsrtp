#define EXTRACT(dest, src, srcsize, copysize)                                  \
    {                                                                          \
        memcpy((dest), (src), (copysize));                                     \
        (src) += (copysize);                                                   \
        (srcsize) -= (copysize);                                               \
    }

/* Extract data if src contains sufficient bytes, otherwise go to end */
#define EXTRACT_IF(dest, src, srcsize, copysize)                               \
    {                                                                          \
        if ((srcsize) < (copysize)) {                                          \
            goto end;                                                          \
        } else {                                                               \
            EXTRACT((dest), (src), (srcsize), (copysize));                     \
        }                                                                      \
    }
#include <stdint.h>
#if UINTPTR_MAX == 0xffffffff
#define FUZZ_32BIT
#elif UINTPTR_MAX == 0xffffffffffffffff
#else
#error "Cannot detect word size"
#endif

typedef srtp_err_status_t (*fuzz_srtp_func)(srtp_t, void *, size_t *, size_t);
typedef srtp_err_status_t (*fuzz_srtp_get_length_func)(const srtp_t,
                                                       size_t,
                                                       size_t *);

static srtp_err_status_t fuzz_srtp_protect(srtp_t srtp_sender,
                                           void *hdr,
                                           size_t *len,
                                           size_t mki);
static srtp_err_status_t fuzz_srtp_unprotect(srtp_t srtp_sender,
                                             void *hdr,
                                             size_t *len,
                                             size_t mki);
static srtp_err_status_t fuzz_srtp_protect_rtcp(srtp_t srtp_sender,
                                                void *hdr,
                                                size_t *len,
                                                size_t mki);
static srtp_err_status_t fuzz_srtp_unprotect_rtcp(srtp_t srtp_sender,
                                                  void *hdr,
                                                  size_t *len,
                                                  size_t mki);

static srtp_err_status_t fuzz_srtp_get_protect_length(const srtp_t srtp_ctx,
                                                      size_t mki,
                                                      size_t *length);
static srtp_err_status_t fuzz_srtp_get_protect_rtcp_length(
    const srtp_t srtp_ctx,
    size_t mki,
    size_t *length);

struct fuzz_srtp_func_ext {
    fuzz_srtp_func srtp_func;
    bool protect;
    fuzz_srtp_get_length_func get_length;
};

const struct fuzz_srtp_func_ext srtp_funcs[] = {
    { fuzz_srtp_protect, true, fuzz_srtp_get_protect_length },
    { fuzz_srtp_unprotect, false, NULL },
    { fuzz_srtp_protect_rtcp, true, fuzz_srtp_get_protect_rtcp_length },
    { fuzz_srtp_unprotect_rtcp, false, NULL }
};

struct fuzz_srtp_profile_ext {
    srtp_profile_t profile;
    const char *name;
};

const struct fuzz_srtp_profile_ext fuzz_srtp_profiles[] = {
    { srtp_profile_null_null, "srtp_profile_null_null" },
    { srtp_profile_aes128_cm_sha1_80, "srtp_profile_aes128_cm_sha1_80" },
    { srtp_profile_aes128_cm_sha1_32, "srtp_profile_aes128_cm_sha1_32" },
    { srtp_profile_aes256_cm_sha1_80, "srtp_profile_aes256_cm_sha1_80" },
    { srtp_profile_aes256_cm_sha1_32, "srtp_profile_aes256_cm_sha1_32" },
    { srtp_profile_null_sha1_80, "srtp_profile_null_sha1_80" },
    { srtp_profile_null_sha1_32, "srtp_profile_null_sha1_32" },
    { srtp_profile_aes192_cm_sha1_80, "srtp_profile_aes192_cm_sha1_80" },
    { srtp_profile_aes192_cm_sha1_32, "srtp_profile_aes192_cm_sha1_32" },
    { srtp_profile_aead_aes_128_gcm, "srtp_profile_aead_aes_128_gcm" },
    { srtp_profile_aead_aes_256_gcm, "srtp_profile_aead_aes_256_gcm" },
};

struct fuzz_srtp_ssrc_type_ext {
    srtp_ssrc_type_t srtp_ssrc_type;
    const char *name;
};

const struct fuzz_srtp_ssrc_type_ext fuzz_ssrc_type_map[] = {
    { ssrc_undefined, "ssrc_undefined" },
    { ssrc_specific, "ssrc_specific" },
    { ssrc_any_inbound, "ssrc_any_inbound" },
    { ssrc_any_outbound, "ssrc_any_outbound" },
};
