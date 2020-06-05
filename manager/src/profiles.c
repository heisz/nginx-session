/**
 * Containers for processing the various manager security profiles/config.
 * 
 * Copyright (C) 2018-2020 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#include "stdconfig.h"
#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <zlib.h>
#include "manager.h"
#include "json.h"
#include "xml.h"
#include "encoding.h"
#include "log.h"
#include "mem.h"

/* Not sure why this isn't generally exposed */
#ifndef DEF_MEM_LEVEL
#if MAX_MEM_LEVEL >= 8
#define DEF_MEM_LEVEL 8
#else
#define DEF_MEM_LEVEL MAX_MEM_LEVEL
#endif
#endif

/****** SAML authentication ******/

/**
 * Core structure for definition of SAML profile instance and associated
 * configuration details.
 */
typedef struct {
    /* Always start with the base 'class' instance */
    NGXMGR_Profile base;

    /* Required configuration elements */
    char *signOnURL;

    /* Optional elements depending on IdP and validation requirements */
    char *entityId;
    char *providerName;
    char *destination;
    int forceAuthn;
    int isPassive;
} SAMLProfile;

/**
 * Configuration binding definitions to parse the above.
 */
static WXJSONBindDefn samlBindings[] = {
    { "signOnURL", WXJSONBIND_STR,
      offsetof(SAMLProfile, signOnURL), TRUE },

    { "entityId", WXJSONBIND_STR,
      offsetof(SAMLProfile, entityId), FALSE },
    { "providerName", WXJSONBIND_STR,
      offsetof(SAMLProfile, providerName), FALSE },
    { "destination", WXJSONBIND_STR,
      offsetof(SAMLProfile, destination), FALSE },
    { "forceAuthn", WXJSONBIND_BOOLEAN,
      offsetof(SAMLProfile, forceAuthn), FALSE },
    { "isPassive", WXJSONBIND_BOOLEAN,
      offsetof(SAMLProfile, isPassive), FALSE }
};

#define SAML_CFG_COUNT (sizeof(samlBindings) / sizeof(WXJSONBindDefn))

/* Forward declare for initialization, instance defined at end */
static NGXMGR_Profile SAMLBaseProfile;

/* Standard initialization method for a SAML profile */
static NGXMGR_Profile *SAMLInit(NGXMGR_Profile *orig, const char *profileName,
                                WXJSONValue *config) {
    SAMLProfile *retval = (SAMLProfile *) orig;
    char errMsg[1024];

    /* First call will not provide a value */
    if (retval == NULL) {
        retval = (SAMLProfile *) WXMalloc(sizeof(SAMLProfile));
        if (retval == NULL) return NULL;

        /* Clone the base element details from the static instance */
        retval->base = SAMLBaseProfile;
        retval->base.name = profileName;

        /* Pre-initialize the configuration details/defaults */
        retval->signOnURL = NULL;
        retval->entityId = NULL;
        retval->providerName = NULL;
        retval->destination = NULL;
        retval->forceAuthn = FALSE;
        retval->isPassive = FALSE;
    }

    /* Bind the configuration data */
    if (!WXJSON_Bind(config, retval, samlBindings, SAML_CFG_COUNT,
                     errMsg, sizeof(errMsg))) {
        /* Possibly memory leak here, turning a blind eye... */
        WXLog_Error("SAML configuration binding error: %s", errMsg);
        return NULL;
    }

    return &(retval->base);
}

static char *allocError = "\01\364" /* Response code 500 */
                          "Internal Error: memory allocation failure.\n";
static char *ssoGenError = "\01\364" /* Response code 500 */
                           "Internal Error: failure in SAML redirect.\n";

/* Processing method for the SAML profile, either post completion or get init */
static void (SAMLProcess)(NGXMGR_Profile *prf, NGXModuleConnection *conn,
                          char *action) {
    char *url, *enc, *sessReqId, xmlBuff[1024], *deflateBuff, tmBuff[64];
    SAMLProfile *profile = (SAMLProfile *) prf;
    WXMLNamespace *samlNs, *samlpNs, authNs;
    WXMLElement *authnReqElmnt = NULL;
    BIO *base64Enc = NULL, *base64Buff;
    z_stream deflateStrm;
    WXBuffer buffer;
    BUF_MEM *bptr;
    time_t now;
    int zrc;

    /* TODO - command for completion?  */

    /* Any fallthrough is a restart of the SAML login sequence */

    /* TODO - Allocate a pending session instance */
    sessReqId = "TEST_123456";

    /* Build the authentication request document based on details and config */
    authNs.prefix = "samlp";
    authNs.href = "urn:oasis:names:tc:SAML:2.0:protocol";
    authNs.origin = NULL;
    authnReqElmnt = WXML_AllocateElement(NULL, "AuthnRequest", &authNs, NULL,
                                         TRUE);
    if (authnReqElmnt == NULL) goto memfail;
    samlpNs = authnReqElmnt->namespace;
    samlNs = WXML_AllocateNamespace(authnReqElmnt, "saml",
                                    "urn:oasis:names:tc:SAML:2.0:assertion",
                                    TRUE);
    if (samlNs == NULL) goto memfail;
    if (WXML_AllocateNamespace(authnReqElmnt, "",
                               "urn:oasis:names:tc:SAML:2.0:metadata",
                               TRUE) == NULL) goto memfail;

    /* First the 'reasonably' fixed attributes */
    if (WXML_AllocateAttribute(authnReqElmnt, "Version", NULL, "2.0", 
                              TRUE) == NULL) goto memfail;
    if (WXML_AllocateAttribute(authnReqElmnt, "ID", NULL, "sessReqId", 
                               TRUE) == NULL) goto memfail;
    if (WXML_AllocateAttribute(authnReqElmnt, "ProtocolBinding", NULL,
                               "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                               TRUE) == NULL) goto memfail;

    /* IssueInstant is in 'round trip format', second resolution is enough */
    time(&now);
    (void) strftime(tmBuff, sizeof(tmBuff), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    if (WXML_AllocateAttribute(authnReqElmnt, "IssueInstant", NULL,
                               tmBuff, TRUE) == NULL) goto memfail;

    /* Then all of the 'optional' attributes */
    if (profile->providerName != NULL) {
        if (WXML_AllocateAttribute(authnReqElmnt, "ProviderName", NULL,
                                   profile->providerName,
                                   TRUE) == NULL) goto memfail;
    }
    if (profile->forceAuthn) {
        if (WXML_AllocateAttribute(authnReqElmnt, "ForceAuthn", NULL,
                                   "true", TRUE) == NULL) goto memfail;
    }
    if (profile->isPassive) {
        if (WXML_AllocateAttribute(authnReqElmnt, "IsPassive", NULL,
                                   "true", TRUE) == NULL) goto memfail;
    }
    if (profile->destination != NULL) {
        if (WXML_AllocateAttribute(authnReqElmnt, "Destination", NULL,
                                   profile->destination,
                                   TRUE) == NULL) goto memfail;
    } else {
        if (WXML_AllocateAttribute(authnReqElmnt, "Destination", NULL,
                                   profile->signOnURL,
                                   TRUE) == NULL) goto memfail;
    }
    /* TODO - Assertion consumer URL */

    if (WXML_AllocateElement(authnReqElmnt, "Issuer", samlNs,
                             profile->entityId, TRUE) == NULL) goto memfail;

    /* Following the spec, compact serialize the XML... */
    WXBuffer_InitLocal(&buffer, xmlBuff, sizeof(xmlBuff));
    if (WXML_Encode(&buffer, authnReqElmnt, FALSE) == NULL) goto memfail;

    /* TODO - remove this when things are stable */
    WXLog_Debug("SAML Auth Request: %s", buffer.buffer);

    /* Note: encoding includes the null terminator (string), remove it */
    buffer.length--;

    /* Then deflate it (first of two frustrations, kept missing it) ... */
    /* Double is at least 0.1% larger than source plus 12 bytes... */
    deflateBuff = (char *) WXMalloc(2 * buffer.length);
    if (deflateBuff == NULL) goto memfail;

    /* Cannot use compress, MUST be raw deflate, no header or checksum!!! */
    deflateStrm.zalloc = Z_NULL;
    deflateStrm.zfree = Z_NULL;
    deflateStrm.opaque = Z_NULL;
    deflateStrm.avail_in = buffer.length;
    deflateStrm.next_in = (Bytef *) buffer.buffer;
    deflateStrm.avail_out = 2 * buffer.length;
    deflateStrm.next_out = (Bytef *) deflateBuff;
    if (((zrc = deflateInit2(&deflateStrm, Z_BEST_COMPRESSION, Z_DEFLATED,
                             -MAX_WBITS, DEF_MEM_LEVEL,
                             Z_DEFAULT_STRATEGY)) != Z_OK) ||
            ((zrc = deflate(&deflateStrm, Z_FINISH)) != Z_STREAM_END) ||
            ((zrc = deflateEnd(&deflateStrm)) != Z_OK)) {
        WXLog_Error("Zlib default failure: [%d] %s", zrc, zError(zrc));
        NGXMGR_IssueResponse(conn, NGXMGR_ERROR_RESPONSE,
                             ssoGenError, strlen(ssoGenError) + 2);
        return;
    }
           
    /* Base64 encode the resulting compressed data ... */
    base64Enc = BIO_new(BIO_f_base64());
    base64Buff = BIO_new(BIO_s_mem());
    if ((base64Enc == NULL) || (base64Buff == NULL)) goto memfail;
    base64Enc = BIO_push(base64Enc, base64Buff);
    BIO_set_flags(base64Enc, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(base64Enc, deflateBuff, deflateStrm.total_out);
    BIO_flush(base64Enc);
    BIO_get_mem_ptr(base64Enc, &bptr);

    /* Finally, generate and issue the encoded URL redirect/request instance */
    WXBuffer_Empty(&buffer);
    if ((WXBuffer_Append(&buffer, profile->signOnURL,
                         strlen(profile->signOnURL), TRUE) == NULL) ||
            (WXBuffer_Append(&buffer, "?SAMLRequest=", 13, TRUE) == NULL) ||
            (WXURL_EscapeURI(&buffer, bptr->data,
                             bptr->length) == NULL)) goto memfail;

    NGXMGR_IssueResponse(conn, NGXMGR_EXTERNAL_REDIRECT,
                         buffer.buffer, buffer.length);
    BIO_free_all(base64Enc);
    return;

memfail:
    if (base64Enc != NULL) BIO_free_all(base64Enc);
    WXLog_Error("Memory allocation failure!");
    NGXMGR_IssueResponse(conn, NGXMGR_ERROR_RESPONSE,
                         allocError, strlen(allocError) + 2);
}

static NGXMGR_Profile SAMLBaseProfile = {
    "saml", NULL, SAMLInit, SAMLProcess
};

static NGXMGR_Profile *profileTypes[] = {
    &SAMLBaseProfile
};

#define PROFILE_TYPE_COUNT (sizeof(profileTypes) / sizeof(NGXMGR_Profile *))

NGXMGR_Profile *NGXMGR_AllocProfile(char *profileName, WXJSONValue *config) {
    WXJSONValue *type;
    char *nm;
    int idx;

    /* First, figure out the corresponding type definition/reference */
    type = WXJSON_Find(config, "type");
    if ((type == NULL) || (type->type != WXJSONVALUE_STRING)) {
        WXLog_Error("Missing or invalid 'type' value for profile");
        return NULL;
    }
    for (idx = 0; idx < PROFILE_TYPE_COUNT; idx++) {
        if (strcasecmp(profileTypes[idx]->type, type->value.sval) == 0) break;
    }
    if (idx >= PROFILE_TYPE_COUNT) {
        WXLog_Error("Unrecognized profile type '%s'", type->value.sval);
        return NULL;
    }

    /* Duplicate the profile name here in commons */
    if ((nm = WXMalloc(strlen(profileName) + 1)) == NULL) return NULL;
    (void) strcpy(nm, profileName);

    /* Pass to the initialization method of the type */
    return (profileTypes[idx]->init)(NULL, nm, config);
}
