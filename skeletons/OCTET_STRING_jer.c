/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OCTET_STRING.h>
#include <BIT_STRING.h>  /* for .bits_unused member */

asn_enc_rval_t
OCTET_STRING_encode_jer(const asn_TYPE_descriptor_t *td, const void *sptr,
                        int ilevel, enum jer_encoder_flags_e flags,
                        asn_app_consume_bytes_f *cb, void *app_key) {
    const char * const h2c = "0123456789ABCDEF";
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
    asn_enc_rval_t er = { 0, 0, 0 };
    char scratch[16 * 3 + 4];
    char *p = scratch;
    uint8_t *buf;
    uint8_t *end;
    size_t i;

    if(!st || (!st->buf && st->size))
        ASN__ENCODE_FAILED;

    er.encoded = 0;

    /*
     * Dump the contents of the buffer in hexadecimal.
     */
    buf = st->buf;
    end = buf + st->size;
    ASN__CALLBACK("\"", 1);
    for(i = 0; buf < end; buf++, i++) {
      if(!(i % 16) && (i || st->size > 16)) {
        ASN__CALLBACK(scratch, p-scratch);
        p = scratch;
      }
      *p++ = h2c[(*buf >> 4) & 0x0F];
      *p++ = h2c[*buf & 0x0F];
    }
    if(p - scratch) {
      ASN__CALLBACK(scratch, p-scratch);  /* Dump the rest */
    }
    ASN__CALLBACK("\"", 1);

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

static const struct OCTET_STRING__jer_escape_table_s {
    const char *string;
    int size;
} OCTET_STRING__jer_escape_table[] = {
#define	OSXET(s)	{ s, sizeof(s) - 1 }
    { 0, 0 },  /* NULL */
    { 0, 0 },  /* Start of header */
    { 0, 0 },  /* Start of text */
    { 0, 0 },  /* End of text */
    { 0, 0 },  /* End of transmission */
    { 0, 0 },  /* Enquiry */
    { 0, 0 },  /* Ack */
    { 0, 0 },  /* Bell */
    OSXET("\134\142"),  /* \b */
    OSXET("\134\164"),  /* \t */
    OSXET("\134\156"),  /* \n */
    { 0, 0 },  /* Vertical tab */
    OSXET("\134\146"),  /* \f */
    OSXET("\134\162"),  /* \r */
    { 0, 0 },  /* Shift out */
    { 0, 0 },  /* Shift in */
    { 0, 0 },  /* Data link escape */
    { 0, 0 },  /* Device control 1 */
    { 0, 0 },  /* Device control 2 */
    { 0, 0 },  /* Device control 3 */
    { 0, 0 },  /* Device control 4 */
    { 0, 0 },  /* Negative ack */
    { 0, 0 },  /* Synchronous idle */
    { 0, 0 },  /* End of transmission block */
    { 0, 0 },  /* Cancel */
    { 0, 0 },  /* End of medium */
    { 0, 0 },  /* Substitute */
    { 0, 0 },  /* Escape */
    { 0, 0 },  /* File separator */
    { 0, 0 },  /* Group separator */
    { 0, 0 },  /* Record separator */
    { 0, 0 },  /* Unit separator */
    { 0, 0 },                           /* " " */
    { 0, 0 },                           /* ! */
    OSXET("\134\042"),                  /* \" */
    { 0, 0 },                           /* # */
    { 0, 0 },                           /* $ */
    { 0, 0 },                           /* % */
    { 0, 0 },  /* &amp; */
    { 0, 0 },                           /* ' */
    {0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},  /* ()*+,-./ */
    {0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},  /* 01234567 */
    {0,0},{0,0},{0,0},{0,0},            /* 89:; */
    { 0, 0 },  /* &lt; */
    { 0, 0 },                           /* = */
    { 0, 0 },  /* &gt; */
    { 0, 0 },  /* ? */
    { 0, 0 },  /* @ */
    {0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0}, /* ABCDEFGH */
    {0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0}, /* IJKLMNOP */
    {0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0},{0,0}, /* QRSTUVWX */
    {0,0},{0,0},                                     /* YZ */
    { 0, 0 },  /* [ */
    OSXET("\134\134"),  /* \\ */
};

static int
OS__check_escaped_control_char(const void *buf, int size) {
    size_t i;
    /*
     * Inefficient algorithm which translates the escape sequences
     * defined above into characters. Returns -1 if not found.
     * TODO: replace by a faster algorithm (bsearch(), hash or
     * nested table lookups).
     */
    for(i = 0; i < 32 /* Don't spend time on the bottom half */; i++) {
        const struct OCTET_STRING__jer_escape_table_s *el;
        el = &OCTET_STRING__jer_escape_table[i];
        if(el->size == size && memcmp(buf, el->string, size) == 0)
            return i;
    }
    return -1;
}

static int
OCTET_STRING__handle_control_chars(void *struct_ptr, const void *chunk_buf, size_t chunk_size) {
    /*
     * This might be one of the escape sequences
     * for control characters. Check it out.
     * #11.15.5
     */
    int control_char = OS__check_escaped_control_char(chunk_buf,chunk_size);
    if(control_char >= 0) {
        OCTET_STRING_t *st = (OCTET_STRING_t *)struct_ptr;
        void *p = REALLOC(st->buf, st->size + 2);
        if(p) {
            st->buf = (uint8_t *)p;
            st->buf[st->size++] = control_char;
            st->buf[st->size] = '\0';  /* nul-termination */
            return 0;
        }
    }

    return -1;  /* No, it's not */
}

asn_enc_rval_t
OCTET_STRING_encode_jer_utf8(const asn_TYPE_descriptor_t *td, const void *sptr,
                             int ilevel, enum jer_encoder_flags_e flags,
                             asn_app_consume_bytes_f *cb, void *app_key) {
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
    asn_enc_rval_t er = { 0, 0, 0 };
    uint8_t *buf, *end;
    uint8_t *ss;  /* Sequence start */
    ssize_t encoded_len = 0;

    (void)ilevel;  /* Unused argument */
    (void)flags;  /* Unused argument */

    if(!st || (!st->buf && st->size))
        ASN__ENCODE_FAILED;

    buf = st->buf;
    end = buf + st->size;
    ASN__CALLBACK("\"", 1);
    for(ss = buf; buf < end; buf++) {
        unsigned int ch = *buf;
        int s_len;	/* Special encoding sequence length */

        /*
         * Escape certain characters
         */
        if(ch < sizeof(OCTET_STRING__jer_escape_table)
            / sizeof(OCTET_STRING__jer_escape_table[0])
        && (s_len = OCTET_STRING__jer_escape_table[ch].size)) {
            if(((buf - ss) && cb(ss, buf - ss, app_key) < 0)
            || cb(OCTET_STRING__jer_escape_table[ch].string, s_len, app_key) < 0)
                ASN__ENCODE_FAILED;
            encoded_len += (buf - ss) + s_len;
            ss = buf + 1;
        }
    }

    encoded_len += (buf - ss);
    if((buf - ss) && cb(ss, buf - ss, app_key) < 0)
        goto cb_failed;

    er.encoded += encoded_len;

    ASN__CALLBACK("\"", 1);
    ASN__ENCODED_OK(er);

cb_failed:
    ASN__ENCODE_FAILED;
}

#define CQUOTE 0x22

/*
 * Convert from hexadecimal format (cstring): "AB CD EF"
 */
static ssize_t OCTET_STRING__convert_hexadecimal(void *sptr, const void *chunk_buf, size_t chunk_size, int have_more) {
    OCTET_STRING_t *st = (OCTET_STRING_t *)sptr;
    const char *chunk_stop = (const char *)chunk_buf;
    const char *p = chunk_stop;
    const char *pend = p + chunk_size;
    unsigned int clv = 0;
    int half = 0;	/* Half bit */
    uint8_t *buf;

    /* Strip quotes */
    for (; p < pend; ++p) {
        if (*p == CQUOTE) {
            ++p;
            break;
        }
    }
    --pend;
    for (; pend >= p; --pend) {
        if (*pend == CQUOTE) 
            break;
    }
    if (pend - p < 0) return -1;
    chunk_size = pend - p;

    /* Reallocate buffer according to high cap estimation */
    size_t new_size = st->size + (chunk_size + 1) / 2;
    void *nptr = REALLOC(st->buf, new_size + 1);
    if(!nptr) return -1;
    st->buf = (uint8_t *)nptr;
    buf = st->buf + st->size;

    /*
     * If something like " a b c " appears here, the " a b":3 will be
     * converted, and the rest skipped. That is, unless buf_size is greater
     * than chunk_size, then it'll be equivalent to "ABC0".
     */
    for(; p < pend; p++) {
        int ch = *(const unsigned char *)p;
        switch(ch) {
        case 0x09: case 0x0a: case 0x0c: case 0x0d:
        case 0x20:
            /* Ignore whitespace */
            continue;
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:  /*01234*/
        case 0x35: case 0x36: case 0x37: case 0x38: case 0x39:  /*56789*/
            clv = (clv << 4) + (ch - 0x30);
            break;
        case 0x41: case 0x42: case 0x43:  /* ABC */
        case 0x44: case 0x45: case 0x46:  /* DEF */
            clv = (clv << 4) + (ch - 0x41 + 10);
            break;
        case 0x61: case 0x62: case 0x63:  /* abc */
        case 0x64: case 0x65: case 0x66:  /* def */
            clv = (clv << 4) + (ch - 0x61 + 10);
            break;
        default:
            *buf = 0;  /* JIC */
            return -1;
        }
        if(half++) {
            half = 0;
            *buf++ = clv;
            chunk_stop = p + 1;
        }
    }

    /*
     * Check partial decoding.
     */
    if(half) {
        if(have_more) {
            /*
             * Partial specification is fine,
             * because no more more PJER_TEXT data is available.
             */
            *buf++ = clv << 4;
            chunk_stop = p;
        }
    } else {
        ++p;
        chunk_stop = p;
    }

    st->size = buf - st->buf;  /* Adjust the buffer size */
    assert(st->size <= new_size);
    st->buf[st->size] = 0;  /* Courtesy termination */

    return (chunk_stop - (const char *)chunk_buf);  /* Converted size */
}

/*
 * Something like strtod(), but with stricter rules.
 */
static int
OS__strtoent(int base, const char *buf, const char *end, int32_t *ret_value) {
	const int32_t last_unicode_codepoint = 0x10ffff;
	int32_t val = 0;
	const char *p;

	for(p = buf; p < end; p++) {
		int ch = *p;

        switch(ch) {
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:  /*01234*/
        case 0x35: case 0x36: case 0x37: case 0x38: case 0x39:  /*56789*/
            val = val * base + (ch - 0x30);
            break;
        case 0x41: case 0x42: case 0x43:  /* ABC */
        case 0x44: case 0x45: case 0x46:  /* DEF */
            val = val * base + (ch - 0x41 + 10);
            break;
        case 0x61: case 0x62: case 0x63:  /* abc */
        case 0x64: case 0x65: case 0x66:  /* def */
            val = val * base + (ch - 0x61 + 10);
            break;
        case 0x3b:  /* ';' */
            *ret_value = val;
            return (p - buf) + 1;
        default:
            return -1;  /* Character set error */
        }

        /* Value exceeds the Unicode range. */
        if(val > last_unicode_codepoint) {
            return -1;
        }
    }

    *ret_value = -1;
    return (p - buf);
}

/*
 * Convert from the plain UTF-8 format
 */
static ssize_t
OCTET_STRING__convert_entrefs(void *sptr, const void *chunk_buf,
                              size_t chunk_size, int have_more) {
    OCTET_STRING_t *st = (OCTET_STRING_t *)sptr;
    const char *p = (const char *)chunk_buf;
    const char *pend = p + chunk_size;
    uint8_t *buf;

    /* Strip quotes */
    for(; p < pend; ++p) {
        if (*p == CQUOTE) {
            ++p;
            break;
        }
    }
    --pend;
    for(; pend >= p; --pend) {
        if (*pend == CQUOTE) 
            break;
    }
    if(pend - p < 0) 
        return -1;

    /* Reallocate buffer */
    size_t new_size = st->size + (pend - p);
    void *nptr = REALLOC(st->buf, new_size + 1);
    if(!nptr) return -1;
    st->buf = (uint8_t *)nptr;
    buf = st->buf + st->size;

    /*
     * Convert series of 0 and 1 into the octet string.
     */
    for(; p < pend; p++) {
        int ch = *(const unsigned char *)p;
        int len;  /* Length of the rest of the chunk */

        if(ch != 0x5c /* '\' */) {
            *buf++ = ch;
            continue;  /* That was easy... */
        }

        /*
         * Process entity reference.
         */
        len = chunk_size - (p - (const char *)chunk_buf);
        if(len == 1 /* "\" */) goto want_more;
        switch(p[1]) {
        case 0x75: /* 'u' */
            ;
            const char *pval;  /* Pointer to start of digits */
            int32_t val = 0;  /* Entity reference value */
            int base;

            if(len == 2 /* "&#" */) goto want_more;
            if(p[2] == 0x78 /* 'x' */)
                pval = p + 3, base = 16;
            else
                pval = p + 2, base = 10;
            len = OS__strtoent(base, pval, p + len, &val);
            if(len == -1) {
                /* Invalid charset. Just copy verbatim. */
                *buf++ = ch;
                continue;
            }
            if(!len || pval[len-1] != 0x3b) goto want_more;
            assert(val > 0);
            p += (pval - p) + len - 1;  /* Advance past entref */

            if(val < 0x80) {
                *buf++ = (char)val;
            } else if(val < 0x800) {
                *buf++ = 0xc0 | ((val >> 6));
                *buf++ = 0x80 | ((val & 0x3f));
            } else if(val < 0x10000) {
                *buf++ = 0xe0 | ((val >> 12));
                *buf++ = 0x80 | ((val >> 6) & 0x3f);
                *buf++ = 0x80 | ((val & 0x3f));
            } else if(val < 0x200000) {
                *buf++ = 0xf0 | ((val >> 18));
                *buf++ = 0x80 | ((val >> 12) & 0x3f);
                *buf++ = 0x80 | ((val >> 6) & 0x3f);
                *buf++ = 0x80 | ((val & 0x3f));
            } else if(val < 0x4000000) {
                *buf++ = 0xf8 | ((val >> 24));
                *buf++ = 0x80 | ((val >> 18) & 0x3f);
                *buf++ = 0x80 | ((val >> 12) & 0x3f);
                *buf++ = 0x80 | ((val >> 6) & 0x3f);
                *buf++ = 0x80 | ((val & 0x3f));
            } else {
                *buf++ = 0xfc | ((val >> 30) & 0x1);
                *buf++ = 0x80 | ((val >> 24) & 0x3f);
                *buf++ = 0x80 | ((val >> 18) & 0x3f);
                *buf++ = 0x80 | ((val >> 12) & 0x3f);
                *buf++ = 0x80 | ((val >> 6) & 0x3f);
                *buf++ = 0x80 | ((val & 0x3f));
            }
            break;
        case 0x22: /* " */
            *buf++ = 0x22;
            ++p;
            break;
        case 0x5c: /* \ */
            *buf++ = 0x5c;
            ++p;
            break;
        case 0x62: /* b */
            *buf++ = 0x08;
            ++p;
            break;
        case 0x66: /* f */
            *buf++ = 0x0c;
            ++p;
            break;
        case 0x6e: /* n */
            *buf++ = 0x0a;
            ++p;
            break;
        case 0x72: /* r */
            *buf++ = 0x0d;
            ++p;
            break;
        case 0x74: /* t */
            *buf++ = 0x09;
            ++p;
            break;
        default:
            /* Unsupported entity reference */
            *buf++ = ch;
            ++p;
            continue;
        }
        continue;
    want_more:
        if(have_more) {
            /*
             * We know that no more data (of the same type)
             * is coming. Copy the rest verbatim.
             */
            *buf++ = ch;
            continue;
        }
        chunk_size = (p - (const char *)chunk_buf);
        /* Processing stalled: need more data */
        break;
    }

    st->size = buf - st->buf;
    assert(st->size <= new_size);
    st->buf[st->size] = 0;  /* Courtesy termination */

    return chunk_size;  /* Converted in full */
}

/*
 * Decode OCTET STRING from the JSON element's value.
 */
static asn_dec_rval_t
OCTET_STRING__decode_jer(
    const asn_codec_ctx_t *opt_codec_ctx, const asn_TYPE_descriptor_t *td,
    void **sptr, const char *opt_mname, const void *buf_ptr, size_t size,
    int (*opt_unexpected_tag_decoder)(void *struct_ptr, const void *chunk_buf,
                                      size_t chunk_size),
    ssize_t (*body_receiver)(void *struct_ptr, const void *chunk_buf,
                             size_t chunk_size, int have_more)) {
    OCTET_STRING_t *st = (OCTET_STRING_t *)*sptr;
    const asn_OCTET_STRING_specifics_t *specs = td->specifics
        ? (const asn_OCTET_STRING_specifics_t *)td->specifics
        : &asn_SPC_OCTET_STRING_specs;
    const char *xml_tag = opt_mname ? opt_mname : td->xml_tag;
    asn_struct_ctx_t *ctx;  /* Per-structure parser context */
    asn_dec_rval_t rval;  /* Return value from the decoder */
    int st_allocated;

    /*
     * Create the string if does not exist.
     */
    if(!st) {
        st = (OCTET_STRING_t *)CALLOC(1, specs->struct_size);
        *sptr = (void *)st;
        if(!st) goto sta_failed;
        st_allocated = 1;
    } else {
        st_allocated = 0;
    }
    if(!st->buf) {
        /* This is separate from above section */
        st->buf = (uint8_t *)CALLOC(1, 1);
        if(!st->buf) {
            if(st_allocated) {
                *sptr = 0;
                goto stb_failed;
            } else {
                goto sta_failed;
            }
        }
    }
   
    /* Restore parsing context */
    ctx = (asn_struct_ctx_t *)(((char *)*sptr) + specs->ctx_offset);

    return jer_decode_general(opt_codec_ctx, ctx, *sptr, xml_tag,
                              buf_ptr, size,
                              opt_unexpected_tag_decoder,
                              body_receiver);

stb_failed:
    FREEMEM(st);
sta_failed:
    rval.code = RC_FAIL;
    rval.consumed = 0;
    return rval;
}

/*
 * Decode OCTET STRING from the hexadecimal data.
 */
asn_dec_rval_t
OCTET_STRING_decode_jer_hex(const asn_codec_ctx_t *opt_codec_ctx,
                            const asn_TYPE_descriptor_t *td, void **sptr,
                            const char *opt_mname, const void *buf_ptr,
                            size_t size) {
    return OCTET_STRING__decode_jer(opt_codec_ctx, td, sptr, opt_mname,
                                    buf_ptr, size, 0,
                                    OCTET_STRING__convert_hexadecimal);
}

/*
 * Decode OCTET STRING from the string (ASCII/UTF-8) data.
 */
asn_dec_rval_t
OCTET_STRING_decode_jer_utf8(const asn_codec_ctx_t *opt_codec_ctx,
                             const asn_TYPE_descriptor_t *td, void **sptr,
                             const char *opt_mname, const void *buf_ptr,
                             size_t size) {
    return OCTET_STRING__decode_jer(opt_codec_ctx, td, sptr, opt_mname,
                                    buf_ptr, size,
                                    OCTET_STRING__handle_control_chars,
                                    OCTET_STRING__convert_entrefs);
}
