/**
 * Containers for processing the various manager security profiles/config.
 * 
 * Copyright (C) 2018-2020 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#include "stdconfig.h"
#include <stddef.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
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

/* These are not defined in manager.h to avoid h-infection */
WXMLLinkedElement *WXML_ValidateSignedReferences(WXMLElement *doc,
                                                 EVP_PKEY *key);
void WXML_FreeLinkedElements(WXMLLinkedElement *list);

/* Maybe move this to the toolkit someday */
static void uriDecode(uint8_t *src) {
    uint8_t h, l, *dst = src;

    while (*src != '\0') {
        if ((*src == '%') &&
                isxdigit(h = *(src + 1)) && isxdigit(l = *(src + 2))) {
            if (h > 'a') h = h - 'a' + 10;
            else if (h > 'A') h = h - 'A' + 10;
            else h = h - '0';

            if (l > 'a') l = l - 'a' + 10;
            else if (l > 'A') l = l - 'A' + 10;
            else l = l - '0';

            *(dst++) = (h << 4) | l;
            src += 3;
        } else {
           *(dst++) = *(src++);
        }
    }
    *dst = '\0';
}

/* Cleanup methods for the following parser */
static int flushHashCB(WXHashTable *table, void *key, void *data,
                       void *userData) {
    /* In this case, the key and data are in the same buffer */
    WXFree(key);
    return 0;
}
static void freeEncodedData(WXHashTable *table) {
    WXHash_Scan(table, flushHashCB, NULL);
    WXHash_Destroy(table);
}

/**
 * Utility method to split and reformat URL-encoded form data into a hashtable
 * of values.
 *
 * @param hash The hashtable to populate with form values.
 * @param data The URL-encoded form data.
 * @param len The length of the form data.
 * @return TRUE if parse was successful, FALSE on memory error.
 */
static int parseFormEncoded(WXHashTable *table, char *data, int len) {
    char *ptr = data, *str, *chunk, *old;
    int l = len, ll;

    /* Outer loop splits on the ampersand */
    while (len > 0) {
        /* Find next separator, bounded by length */
        str = ptr;
        while (l > 0) {
            if (*str == '&') break;
            str++; l--;
        }

        /* Allocate copy, used to contain both key and value */
        ll = str - ptr;
        chunk = WXMalloc(ll + 1);
        if (chunk == NULL) {
            WXHash_Destroy(table);
            return FALSE;
        }
        (void) memcpy(chunk, ptr, ll);
        chunk[ll++] = '\0';
        ptr += ll; len -= ll;

        /* Split by equals, then condense the key and value in place */
        str = chunk;
        while (*str != '\0') {
            if (*str == '=') {
                *(str++) = '\0';
                break;
            }
            str++;
        }
        uriDecode((uint8_t *) chunk);
        uriDecode((uint8_t *) str);

        /* And insert into hash, replacing existing values */
        if (!WXHash_PutEntry(table, chunk, str, (void **) &old, NULL,
                             WXHash_StrHashFn,
                             WXHash_StrEqualsFn)) {
            WXHash_Destroy(table);
            WXFree(chunk);
            return FALSE;
        }
        if (old != NULL) WXFree(old);
    }

    return TRUE;
}

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
    char *idpEntityId;

    /* Optional elements depending on IdP and validation requirements */
    char *entityId;
    char *providerName;
    char *destination;
    int forceAuthn;
    int isPassive;
    char *encodedCert;

    /* Derived elements from configuration */
    X509 *idpCertificate;
} SAMLProfile;

/**
 * Configuration binding definitions to parse the above.
 */
static WXJSONBindDefn samlBindings[] = {
    { "signOnURL", WXJSONBIND_STR,
      offsetof(SAMLProfile, signOnURL), TRUE },
    { "idpEntityId", WXJSONBIND_STR,
      offsetof(SAMLProfile, idpEntityId), TRUE },

    { "entityId", WXJSONBIND_STR,
      offsetof(SAMLProfile, entityId), FALSE },
    { "providerName", WXJSONBIND_STR,
      offsetof(SAMLProfile, providerName), FALSE },
    { "destination", WXJSONBIND_STR,
      offsetof(SAMLProfile, destination), FALSE },
    { "forceAuthn", WXJSONBIND_BOOLEAN,
      offsetof(SAMLProfile, forceAuthn), FALSE },
    { "isPassive", WXJSONBIND_BOOLEAN,
      offsetof(SAMLProfile, isPassive), FALSE },
    { "idpCertificate", WXJSONBIND_STR,
      offsetof(SAMLProfile, encodedCert), FALSE }
};

#define SAML_CFG_COUNT (sizeof(samlBindings) / sizeof(WXJSONBindDefn))

/* Forward declare for initialization, instance defined at end */
static NGXMGR_Profile SAMLBaseProfile;

/* Standard initialization method for a SAML profile */
static NGXMGR_Profile *SAMLInit(NGXMGR_Profile *orig, const char *profileName,
                                WXJSONValue *config) {
    SAMLProfile *retval = (SAMLProfile *) orig;
    char errMsg[1024];
    BIO *bio;
    size_t l;

    /* First call will not provide a value */
    if (retval == NULL) {
        retval = (SAMLProfile *) WXMalloc(sizeof(SAMLProfile));
        if (retval == NULL) return NULL;

        /* Clone the base element details from the static instance */
        retval->base = SAMLBaseProfile;
        retval->base.name = profileName;

        /* Pre-initialize the configuration details/defaults */
        retval->signOnURL = NULL;
        retval->idpEntityId = NULL;

        retval->entityId = NULL;
        retval->providerName = NULL;
        retval->destination = NULL;
        retval->forceAuthn = FALSE;
        retval->isPassive = FALSE;
        retval->encodedCert = FALSE;

        retval->idpCertificate = NULL;
    }

    /* Bind the configuration data */
    if (!WXJSON_Bind(config, retval, samlBindings, SAML_CFG_COUNT,
                     errMsg, sizeof(errMsg))) {
        /* Possibly memory leak here, turning a blind eye... */
        WXLog_Error("SAML configuration binding error: %s", errMsg);
        return NULL;
    }

    /* Post-process the validation certificate, if provided */
    if (retval->idpCertificate != NULL) {
        X509_free(retval->idpCertificate);
        retval->idpCertificate = NULL;
    }
    if ((retval->encodedCert != NULL) &&
            ((l = strlen(retval->encodedCert)) != 0)) {
        bio = BIO_new(BIO_s_mem());
        if ((bio == NULL) || (BIO_write(bio, retval->encodedCert, l) != l)) {
            WXLog_Error("Memory failure allocating certificate content");
            if (bio != NULL) BIO_free_all(bio);
            return NULL;
        }

        retval->idpCertificate = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free_all(bio);
        if (retval->idpCertificate == NULL) {
            WXLog_Error("Failed to parse X509 PEM encoded certificate");
            return NULL;
        }

        WXLog_Debug("Loaded IdP Certificate for %s",
                    X509_NAME_oneline(X509_get_subject_name(
                                               retval->idpCertificate),
                                      errMsg, sizeof(errMsg)));
    } else {
        WXLog_Warn("\n\nWARNING: No IdP validation certificate provided!!!!\n"
          "This exposes your SAML SP to injection replay attacks, and should\n"
          "ONLY be enabled under emergency conditions where the validation\n"
          "code is failing unexpectedly (and maybe not even then).\n");
    }

    return &(retval->base);
}

/* Verify processing method for the SAML profile, establish new session */
static void SAMLProcessVerify(NGXMGR_Profile *prf, NGXModuleConnection *conn,
                              char *request) {
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

    /* Initialize this up front for cleanup */
    WXBuffer_InitLocal(&buffer, xmlBuff, sizeof(xmlBuff));

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

    /* TODO - Assertion consumer URL? */

    /* This is optional in config but often required */
    if (profile->entityId != NULL) {
        if (WXML_AllocateElement(authnReqElmnt, "Issuer", samlNs,
                                 profile->entityId, TRUE) == NULL) goto memfail;
    }

    /* TODO - name ID policy for AllowCreate support? */

    /* Authn document is now complete */

    /* Following the spec, compact serialize the XML... */
    if (WXML_Encode(&buffer, authnReqElmnt, FALSE) == NULL) goto memfail;
    WXML_Destroy(authnReqElmnt); authnReqElmnt = NULL;

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
        NGXMGR_IssueErrorResponse(conn, 500, "Internal Manager Error",
                           "Internal Error: failure in SAML redirect");
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
    WXFree(deflateBuff); deflateBuff = NULL;

    /* TODO - RelayState determination? */

    /* Finally, generate and issue the encoded URL redirect/request instance */
    WXBuffer_Empty(&buffer);
    if ((WXBuffer_Append(&buffer, profile->signOnURL,
                         strlen(profile->signOnURL), TRUE) == NULL) ||
            (WXBuffer_Append(&buffer, "?SAMLRequest=", 13, TRUE) == NULL) ||
            (WXURL_EscapeURI(&buffer, bptr->data,
                             bptr->length) == NULL)) goto memfail;

    /* Tally ho! */
    NGXMGR_IssueResponse(conn, NGXMGR_EXTERNAL_REDIRECT,
                         buffer.buffer, buffer.length);
    BIO_free_all(base64Enc);
    WXBuffer_Destroy(&buffer);

    return;

memfail:
    if (authnReqElmnt != NULL) WXML_Destroy(authnReqElmnt);
    if (base64Enc != NULL) BIO_free_all(base64Enc);
    if (deflateBuff != NULL) WXFree(deflateBuff);
    WXBuffer_Destroy(&buffer);
    WXLog_Error("Memory allocation failure!");
    NGXMGR_IssueErrorResponse(conn, 500, "Memory Error",
                       "Internal Error: Manager memory allocation error");
}

static void logXML(WXMLElement *root) {
    WXBuffer buffer;

    WXBuffer_Init(&buffer, 1024);
    WXML_Encode(&buffer, root, TRUE);
    WXLog_Debug("XML:\n%s", buffer.buffer);
    WXBuffer_Destroy(&buffer);
}

/* Process SAML commands, establish login completion or logout */
static void SAMLLogin(NGXMGR_Profile *prf, NGXModuleConnection *conn,
                      char *data, int dataLen) {
    char *samlResp, *decSamlResp = NULL, errorMsg[1024];
    SAMLProfile *profile = (SAMLProfile *) prf;
    WXMLLinkedElement *signedRefs = NULL;
    BIO *base64Dec, *base64Buff = NULL;
    WXMLElement *root = NULL;
    WXHashTable postData;
    int len;

    /* Decode the form arguments */
    if ((!WXHash_InitTable(&postData, 16)) ||
            (!parseFormEncoded(&postData, data, dataLen))) goto memfail;

    /* Pull the saml response, prep for decoding */
    samlResp = WXHash_GetEntry(&postData, "SAMLResponse",
                               WXHash_StrHashFn, WXHash_StrEqualsFn);
    if (samlResp == NULL) {
        NGXMGR_IssueErrorResponse(conn, 500, "Invalid SAML Response",
                          "Verify response missing SAMLResponse data element");
        return;
    }
    len = strlen(samlResp);
    decSamlResp = WXMalloc(len + 2);
    if (decSamlResp == NULL) goto memfail;

    /* It's base64 encoded XML content */
    base64Buff = BIO_new_mem_buf(samlResp, len);
    base64Dec = BIO_new(BIO_f_base64());
    if ((base64Buff == NULL) || (base64Dec == NULL)) goto memfail;
    base64Buff = BIO_push(base64Dec, base64Buff);
    BIO_set_flags(base64Buff, BIO_FLAGS_BASE64_NO_NL);
    len = BIO_read(base64Buff, decSamlResp, len);
    decSamlResp[len] = '\0';
    BIO_free_all(base64Buff); base64Buff = NULL;

    root = WXML_Decode(decSamlResp, TRUE, errorMsg, sizeof(errorMsg));
    WXFree(decSamlResp); decSamlResp = NULL;
    if (root == NULL) {
        WXLog_Error("Invalid SAML XML response: %s", errorMsg);
        NGXMGR_IssueErrorResponse(conn, 400, "Invalid SAML Response",
                          "Unable to parse XML content of SAML response");
        WXHash_Destroy(&postData);
        return;
    }

    /* TODO -remove when stable */
    logXML(root);

    /* First, determine the validated references up front (if enabled) */
    if (profile->idpCertificate != NULL) {
        signedRefs = WXML_ValidateSignedReferences(root,
                                  X509_get_pubkey(profile->idpCertificate));
        if (signedRefs == NULL) {
            /* Either internal error or bad signatures, invalid response */
            NGXMGR_IssueErrorResponse(conn, 401, "Unauthorized (SAML)",
                        "Invalid signed SAML response or error in processing");
            WXHash_Destroy(&postData);
            return;
        }
    }

    /* Bogus for now! */
    NGXMGR_IssueErrorResponse(conn, 500, "It's an error!",
                              "Test '%s' %d", "test", 12);

    /* Cleanup */
    if (signedRefs != NULL) WXML_FreeLinkedElements(signedRefs);
    freeEncodedData(&postData);
    WXML_Destroy(root);

    return;

memfail:
    WXLog_Error("Memory allocation failure!");
    if (postData.entries != NULL) freeEncodedData(&postData);
    if (base64Buff != NULL) BIO_free_all(base64Buff);
    if (decSamlResp != NULL) WXFree(decSamlResp);
    if (root != NULL) WXML_Destroy(root);
    NGXMGR_IssueErrorResponse(conn, 500, "Memory Error",
                       "Internal Error: Manager memory allocation error");
}

static void SAMLProcessAction(NGXMGR_Profile *prof, NGXModuleConnection *conn,
                              char *request, char *action, char *sessionId,
                              char *data, int dataLen) {
    if ((strcmp(action, "login") == 0) && (strncmp(request, "PST", 3) == 0)) {
        SAMLLogin(prof, conn, data, dataLen);
    } else {
        WXLog_Error("Unrecognized action/request: %s - %s", action, request);
        NGXMGR_IssueErrorResponse(conn, 400, "Invalid SAML Configuration",
                          "Invalid SAML configuration and/or response");
    }
}

static NGXMGR_Profile SAMLBaseProfile = {
    "saml", NULL, SAMLInit, SAMLProcessVerify, SAMLProcessAction
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
