/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <BIT_STRING.h>

asn_enc_rval_t
BIT_STRING_encode_jer(const asn_TYPE_descriptor_t *td, const void *sptr,
                      int ilevel, enum jer_encoder_flags_e flags,
                      asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};
    char scratch[128];
    char *p = scratch;
    char *scend = scratch + (sizeof(scratch) - 4);
    const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
    int xcan = 1;
    uint8_t *buf;
    uint8_t *end;

    if(!st || !st->buf)
        ASN__ENCODE_FAILED;

    er.encoded = 0;

    buf = st->buf;
    end = buf + st->size - 1;  /* Last byte is special */

    /*
     * Binary dump
     */
    *p++ = '"';
    for(; buf < end; buf++) {
        int v = *buf;
        int nline = xcan?0:(((buf - st->buf) % 8) == 0);
        if(p >= scend || nline) {
            ASN__CALLBACK(scratch, p - scratch);
            p = scratch;
            if(nline) ASN__TEXT_INDENT(1, ilevel);
        }
        p += sprintf(p, "%02x", v);
    }

    if(!xcan && ((buf - st->buf) % 8) == 0)
        ASN__TEXT_INDENT(1, ilevel);
    ASN__CALLBACK(scratch, p - scratch);
    p = scratch;

    if(buf == end) {
        uint8_t v = *buf;
        int ubits = st->bits_unused;
        p += sprintf(p, "%02x", v & (0xff << ubits));
        ASN__CALLBACK(scratch, p - scratch);
        p = scratch;
    }
    *p++ = '"';
    ASN__CALLBACK(scratch, p - scratch);
    ASN__TEXT_INDENT(1, ilevel - 1);

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}
