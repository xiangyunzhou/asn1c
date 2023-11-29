/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_SET.h>

/*
 * Return a standardized complex structure.
 */
#undef RETURN
#define RETURN(_code)                     \
    do {                                  \
        rval.code = _code;                \
        rval.consumed = consumed_myself;  \
        return rval;                      \
    } while(0)

/*
 * Check whether we are inside the extensions group.
 */
#define IN_EXTENSION_GROUP(specs, memb_idx)                \
    ((specs)->first_extension >= 0                         \
     && (unsigned)(specs)->first_extension <= (memb_idx))

#undef JER_ADVANCE
#define JER_ADVANCE(num_bytes)            \
    do {                                  \
        size_t num = (num_bytes);         \
        ptr = ((const char *)ptr) + num;  \
        size -= num;                      \
        consumed_myself += num;           \
    } while(0)

#define JER_SAVE_STATE                        \
    do {                                      \
        ptr0 = ptr;                           \
        size0 = size;                         \
        consumed_myself0 = consumed_myself;   \
        context0 = ctx->context;\
    } while(0)

#define JER_RESTORE_STATE                     \
    do {                                      \
        ptr = ptr0;                           \
        size = size0;                         \
        consumed_myself = consumed_myself0;   \
        ctx->context = context0;        \
    } while(0)

/*
 * Decode the JER (JSON) data.
 */
asn_dec_rval_t
SET_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                    const asn_TYPE_descriptor_t *td, void **struct_ptr,
                    const char *opt_mname, const void *ptr, size_t size) {
    /*
     * Bring closer parts of structure description.
     */
    const asn_SET_specifics_t *specs
        = (const asn_SET_specifics_t *)td->specifics;
    asn_TYPE_member_t *elements = td->elements;
    const char *json_key = opt_mname ? opt_mname : td->xml_tag;

    /*
     * ... and parts of the structure being constructed.
     */
    void *st = *struct_ptr;  /* Target structure. */
    asn_struct_ctx_t *ctx;   /* Decoder context */

    asn_dec_rval_t rval;          /* Return value from a decoder */
    ssize_t consumed_myself = 0;  /* Consumed bytes from ptr */
    ssize_t edx = -1;                   /* Element index */

    /*
     * Create the target structure if it is not present already.
     */
    if(st == 0) {
        st = *struct_ptr = CALLOC(1, specs->struct_size);
        if(st == 0) RETURN(RC_FAIL);
    }

    /*
     * Restore parsing context.
     */
    ctx = (asn_struct_ctx_t *)((char *)st + specs->ctx_offset);

    asn_dec_rval_t tmprval = {0};
    /* Restore vars */
    const void* ptr0 = ptr;
    size_t size0 = size;
    ssize_t consumed_myself0 = consumed_myself;  /* Consumed bytes from ptr */
    int context0 = ctx->context;

    /*
     * Phases of JER/JSON processing:
     * Phase 0: Check that the key matches our expectations.
     * Phase 1: Processing body and reacting on closing key.
     * Phase 2: Processing inner type.
     * Phase 3: Skipping unknown extensions.
     * Phase 4: PHASED OUT
     */
    for(edx = ctx->step; ctx->phase <= 3;) {
        pjer_chunk_type_e ch_type;  /* JER chunk type */
        ssize_t ch_size;            /* Chunk size */
        jer_check_sym_e scv;        /* Tag check value */
        asn_TYPE_member_t *elm;


        /*
         * Go inside the inner member of a sequence.
         */
        if(ctx->phase == 2) {
            void *memb_ptr_dontuse;  /* Pointer to the member */
            void **memb_ptr2;        /* Pointer to that pointer */

            elm = &td->elements[edx];
            if(elm->flags & ATF_POINTER) {
                /* Member is a pointer to another structure */
                memb_ptr2 = (void **)((char *)st + elm->memb_offset);
            } else {
                memb_ptr_dontuse = (char *)st + elm->memb_offset;
                memb_ptr2 = &memb_ptr_dontuse;  /* Only use of memb_ptr_dontuse */
            }

            if(elm->flags & ATF_OPEN_TYPE) {
                //tmprval = OPEN_TYPE_xer_get(opt_codec_ctx, td, st, elm, ptr, size);
            } else {
                /* Invoke the inner type decoder, m.b. multiple times */
                tmprval = elm->type->op->jer_decoder(opt_codec_ctx,
                                                     elm->type, memb_ptr2, elm->name,
                                                     ptr, size);
            }
            JER_ADVANCE(tmprval.consumed);
            if(tmprval.code != RC_OK)
                RETURN(tmprval.code);
            ctx->phase = 1;  /* Back to body processing */
            ctx->step = ++edx;
            ASN_DEBUG("JER/SEQUENCE phase => %d, step => %d",
                ctx->phase, ctx->step);
            /* Fall through */
        }

        /*
         * Get the next part of the JSON stream.
         */
        ch_size = jer_next_token(&ctx->context, ptr, size,
            &ch_type);
        if(ch_size == -1) {
            RETURN(RC_FAIL);
        } else {
            switch(ch_type) {
            case PJER_WMORE:
                RETURN(RC_WMORE);

            case PJER_TEXT:  /* Ignore free-standing text */
                JER_ADVANCE(ch_size);  /* Skip silently */
                continue;

            case PJER_DLM:
            case PJER_VALUE:  /* Ignore free-standing text */
            case PJER_KEY:
                break;  /* Check the rest down there */
            }
        }

        scv = jer_check_sym(ptr, ch_size, ctx->phase == 0 ? json_key : NULL);
        ASN_DEBUG("JER/SEQUENCE: scv = %d, ph=%d [%s]",
                  scv, ctx->phase, json_key);


        /* Skip the extensions section */
        if(ctx->phase == 3) {
            switch(jer_skip_unknown(scv, &ctx->left)) {
            case -1:
                ctx->phase = 4;
                RETURN(RC_FAIL);
            case 0:
                JER_ADVANCE(ch_size);
                continue;
            case 1:
                JER_ADVANCE(ch_size);
                ctx->phase = 1;
                continue;
            case 2:
                ctx->phase = 1;
                break;
            }
        }

        switch(scv) {
        case JCK_OEND:
            if(ctx->phase == 0) break;
            ctx->phase = 0;
            /* Fall through */

        case JCK_KEY:
        case JCK_COMMA:
            if(ctx->phase == 0) {
                JER_ADVANCE(ch_size);
                ctx->phase = 1;  /* Processing body phase */
                continue;
            }

            /* Fall through */
        case JCK_UNKNOWN:
        case JCK_OSTART:
            ASN_DEBUG("JER/SEQUENCE: scv=%d, ph=%d, edx=%" ASN_PRI_SIZE "",
                      scv, ctx->phase, edx);
            if(ctx->phase != 1) {
                break;  /* Really unexpected */
            }

            if (td->elements_count == 0) {
                JER_ADVANCE(ch_size);
                continue;
            }

            if(edx < td->elements_count) {
                JER_ADVANCE(ch_size);
                /*
                 * We have to check which member is next.
                 */
                JER_SAVE_STATE;
                ctx->context = 0;

                ch_size = jer_next_token(&ctx->context, ptr, size, &ch_type);
                if(ch_size == -1) {
                    RETURN(RC_FAIL);
                } 

                if(ch_type != PJER_KEY) {
                    JER_ADVANCE(ch_size); /* Skip silently */
                    ch_size = jer_next_token(&ctx->context, ptr, size, &ch_type);
                    if(ch_size == -1) {
                        RETURN(RC_FAIL);
                    } 
                }

                size_t n;
                size_t edx_end = edx + elements[edx].optional + 1;
                if(edx_end > td->elements_count) {
                    edx_end = td->elements_count;
                }

                for(n = edx; n < edx_end; n++) {
                    elm = &td->elements[n];
                    scv = jer_check_sym(ptr, ch_size, elm->name);
                    switch (scv) {
                        case JCK_KEY:
                            ctx->step = edx = n;
                            ctx->phase = 2;
                            break;
                        case JCK_UNKNOWN:
                            continue;
                        default:
                            n = edx_end;
                            break; /* Phase out */
                    }
                    break;
                }
                JER_RESTORE_STATE;
                if(n != edx_end) 
                    continue;
            } else {
                ASN_DEBUG("Out of defined members: %" ASN_PRI_SIZE "/%u",
                          edx, td->elements_count);
            }

            /* It is expected extension */
            if(specs->extensible) {
                ASN_DEBUG("Got anticipated extension");
                ctx->left = 1;
                ctx->phase = 3;  /* Skip ...'s */
                JER_ADVANCE(ch_size);
                continue;
            }

            /* Fall through */
        default:
            break;
        }

        ASN_DEBUG("Unexpected XML key in SEQUENCE [%c%c%c%c%c%c]",
                  size>0?((const char *)ptr)[0]:'.',
                  size>1?((const char *)ptr)[1]:'.',
                  size>2?((const char *)ptr)[2]:'.',
                  size>3?((const char *)ptr)[3]:'.',
                  size>4?((const char *)ptr)[4]:'.',
                  size>5?((const char *)ptr)[5]:'.');
        break;
    }

    ctx->phase = 4;  /* "Phase out" on hard failure */
    RETURN(RC_FAIL);
}


asn_enc_rval_t
SET_encode_jer(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
               enum jer_encoder_flags_e flags, asn_app_consume_bytes_f *cb,
               void *app_key) {
    const asn_SET_specifics_t *specs = (const asn_SET_specifics_t *)td->specifics;
    asn_enc_rval_t er;
    int xcan = 0;
    const asn_TYPE_tag2member_t *t2m = specs->tag2el_cxer;
    size_t t2m_count = specs->tag2el_cxer_count;
    size_t edx;

    if(!sptr)
        ASN__ENCODE_FAILED;

    assert(t2m_count == td->elements_count);

    er.encoded = 0;

    for(edx = 0; edx < t2m_count; edx++) {
        asn_enc_rval_t tmper;
        asn_TYPE_member_t *elm;
        const void *memb_ptr;
        const char *mname;
        size_t mlen;

        elm = &td->elements[t2m[edx].el_no];
        mname = elm->name;
        mlen = strlen(elm->name);

        if(elm->flags & ATF_POINTER) {
            memb_ptr =
                *(const void *const *)((const char *)sptr + elm->memb_offset);
            if(!memb_ptr) {
                if(elm->optional)
                    continue;
                /* Mandatory element missing */
                ASN__ENCODE_FAILED;
            }
        } else {
            memb_ptr = (const void *)((const char *)sptr + elm->memb_offset);
        }

        if(!xcan)
            ASN__TEXT_INDENT(1, ilevel);
        ASN__CALLBACK3("\"", 1, mname, mlen, "\"", 1);

        /* Print the member itself */
        tmper = elm->type->op->jer_encoder(elm->type, memb_ptr,
                                           ilevel + 1, flags,
                                           cb, app_key);
        if(tmper.encoded == -1) return tmper;
        er.encoded += tmper.encoded;

        //        ASN__CALLBACK3("</", 2, mname, mlen, ">", 1);
    }

    if(!xcan) ASN__TEXT_INDENT(1, ilevel - 1);

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}
