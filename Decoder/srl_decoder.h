#ifndef SRL_DECODER_H_
#define SRL_DECODER_H_

#include "EXTERN.h"
#include "perl.h"
#include "assert.h"

typedef struct PTABLE * ptable_ptr;
typedef struct {
    unsigned char *buf_start;           /* ptr to "physical" start of input buffer */
    unsigned char *buf_end;             /* ptr to end of input buffer */
    unsigned char *pos;                 /* ptr to current position within input buffer */
    unsigned char *save_pos;

    U32 flags;                          /* flag-like options: See F_* defines in srl_decoder.c */
    unsigned int depth;                 /* current Perl-ref recursion depth */
    ptable_ptr ref_seenhash;            /* ptr table for avoiding circular refs */
    ptable_ptr ref_stashes;             /* ptr table for tracking stashes we will bless into - key: ofs, value: stash */
    ptable_ptr ref_bless_av;            /* ptr table for tracking which objects need to be bless - key: ofs, value: mortal AV (of refs)  */
    AV* weakref_av;
} srl_decoder_t;

/* constructor; don't need destructor, this sets up a callback */
srl_decoder_t *srl_build_decoder_struct(pTHX_ HV *opt);
/* Set data for a decoding operation */
void srl_begin_decoding(pTHX_ srl_decoder_t *dec, SV *src);

/* Explicit destructor */
void srl_destroy_decoder(pTHX_ srl_decoder_t *dec);
/* Clear decoder for reuse */
void srl_clear_decoder(pTHX_ srl_decoder_t *dec);

/* Read Sereal packet header from buffer */
int srl_read_header(pTHX_ srl_decoder_t *dec);

/* Start deserializing a top-level SV */
SV *srl_read_single_value(pTHX_ srl_decoder_t *dec, U8* track_pos);

/* Read Sereal packet header from buffer */
int srl_finalize_structure(pTHX_ srl_decoder_t *dec);

#define BUF_POS(dec) ((dec)->pos)
#define BUF_SPACE(dec) ((dec)->buf_end - (dec)->pos)
#define BUF_POS_OFS(dec) ((dec)->pos - (dec)->buf_start)
#define BUF_SIZE(dec) ((dec)->buf_end - (dec)->buf_start)
#define BUF_NOT_DONE(dec) ((dec)->pos < (dec)->buf_end)
#define BUF_DONE(dec) ((dec)->pos >= (dec)->buf_end)


#define MYCROAK(fmt, args...) croak("Sereal: Error in %s line %u: " fmt, __FILE__, __LINE__ , ## args)

#define ERROR_UNIMPLEMENTED(dec,tag,str) STMT_START {   \
    warn("Tag %u %s is unimplemented at ofs: %d",       \
         tag,str, (int)BUF_POS_OFS(dec));               \
    return NULL;                                        \
} STMT_END 
#define ERROR_UNTERMINATED(dec,tag,str) STMT_START {    \
    warn("Tag %u %s was not terminated properly at ofs "\
         "%lu with %lu to go",                          \
         tag, str,dec->pos - dec->buf_start,            \
         dec->buf_end - dec->pos);                      \
    return NULL;                                        \
} STMT_END 

#define WARN_BAD_COPY(dec, tag) warn("While processing tag %u encountered a bad COPY tag", tag)
#define WARN_UNEXPECTED(dec, msg) warn("Unexpected tag %u while expecting %s", *(dec)->pos, msg)
#define WARN_PANIC(dec, msg) warn("Panic: %s", msg);

/* if set, the decoder struct needs to be cleared instead of freed at
 * the end of a deserialization operation */
#define SRL_F_REUSE_DECODER 1UL
#define SRL_DEC_HAVE_OPTION(dec, flag_num) ((dec)->flags & flag_num)

#define FAIL 1
#define SUCCESS 0

#define OR_RETURN(expr, rv) if (expect_false( !(expr) )) return(rv)
#define AND_RETURN(expr, rv) if (expect_false( (expr) )) return(rv)

#define OR_RETURN_FAIL(expr) OR_RETURN(expr, FAIL)
#define AND_RETURN_FAIL(expr) AND_RETURN(expr, FAIL)

#define OR_RETURN_NULL(expr) OR_RETURN(expr, NULL)
#define AND_RETURN_NULL(expr) AND_RETURN(expr, NULL)

#define OR_RETURN_refcnt(expr, rv, maybesv) STMT_START {    \
        if (expect_false( !(expr) )) {                      \
            if (maybesv)                                    \
                SvREFCNT_dec(maybesv);                      \
            return(rv);                                     \
        }                                                   \
    } STMT_END
#define AND_RETURN_refcnt(expr, rv, maybesv) STMT_START {   \
        if (expect_false( (expr) )) {                       \
            if (maybesv)                                    \
                SvREFCNT_dec(maybesv);                      \
            return(rv);                                     \
        }                                                   \
    } STMT_END

#define OR_RETURN_FAIL_refcnt(expr, maybesv) OR_RETURN_refcnt(expr, FAIL, maybesv)
#define AND_RETURN_FAIL_refcnt(expr, maybesv) AND_RETURN_refcnt(expr, FAIL, maybesv)

#define OR_RETURN_NULL_refcnt(expr, maybesv) OR_RETURN_refcnt(expr, NULL, maybesv)
#define AND_RETURN_NULL_refcnt(expr, maybesv) AND_RETURN_refcnt(expr, NULL, maybesv)

#define OR_DO_RETURN(expr, rv, stmt) STMT_START {   \
        if (expect_false( !(expr) )) {              \
            stmt;                                   \
            return(rv);                             \
        }                                           \
    } STMT_END
#define AND_DO_RETURN(expr, rv, stmt) STMT_START {  \
        if (expect_false( (expr) )) {               \
            stmt;                                   \
            return(rv);                             \
        }                                           \
    } STMT_END

#define OR_DO_RETURN_FAIL(expr, stmt) OR_DO_RETURN(expr, FAIL, stmt)
#define AND_DO_RETURN_FAIL(expr, stmt) AND_DO_RETURN(expr, FAIL, stmt)
#define OR_DO_RETURN_NULL(expr, stmt) OR_DO_RETURN(expr, NULL, stmt)
#define AND_DO_RETURN_NULL(expr, stmt) AND_DO_RETURN(expr, NULL, stmt)

#define ASSERT_BUF_SPACE_FAIL(dec,len) STMT_START {                 \
    AND_DO_RETURN_FAIL(                                             \
        (UV)BUF_SPACE((dec)) < (UV)(len),                           \
        warn("Unexpected termination of packet, want %lu bytes, "   \
             "only have %lu available",                             \
             (UV)(len), (UV)BUF_SPACE((dec)))                       \
    );                                                              \
} STMT_END

#define WARN_BUF_SPACE(dec, len)                                    \
        warn("Unexpected termination of packet, want %lu bytes, "   \
             "only have %lu available",                             \
             (UV)(len), (UV)BUF_SPACE((dec)))

#define ASSERT_BUF_SPACE_NULL(dec,len) STMT_START {                 \
    AND_DO_RETURN_NULL(                                             \
        (UV)BUF_SPACE((dec)) < (UV)(len),                           \
        WARN_BUF_SPACE(dec, len);                                   \
    );                                                              \
} STMT_END

#define ASSERT_BUF_SPACE_DO_RETURN_NULL(dec,len,stmt) STMT_START {  \
    if (expect_false( (UV)BUF_SPACE((dec)) < (UV)(len) )) {         \
        WARN_BUF_SPACE(dec, len);                                   \
        stmt;                                                       \
    }                                                               \
} STMT_END

/* #define ASSERT_BUF_SPACE(dec,len) STMT_START {              \
    if (expect_false( (UV)BUF_SPACE((dec)) < (UV)(len) )) { \
        MYCROAK("Unexpected termination of packet, want %lu bytes, only have %lu available", (UV)(len), (UV)BUF_SPACE((dec)));  \
    }                                                       \
} STMT_END
*/

#endif
