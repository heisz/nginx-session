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

/****** Standard/Common Profile Elements ******/

static WXJSONBindDefn stdBindings[] = {
    { "defaultIndex", WXJSONBIND_STR,
      offsetof(NGXMGR_Profile, defaultIndex), FALSE },
    { "sessionIPLocked", WXJSONBIND_BOOLEAN,
      offsetof(NGXMGR_Profile, sessionIPLocked), FALSE }
};

#define STD_CFG_COUNT (sizeof(stdBindings) / sizeof(WXJSONBindDefn))

static int extAttrScanner(WXHashTable *table, void *key, void *obj,
                          void *userData) {
    WXDictionary *extAttr = (WXDictionary *) userData;
    WXJSONValue *val = (WXJSONValue *) obj;

    if (val->type == WXJSONVALUE_STRING) {
        if (!WXDict_PutEntry(extAttr, (char *) key, val->value.sval)) {
            WXLog_Error("Memory failure defining external attribute map");
        }
    } else {
        WXLog_Error("Invalid externalAttributes entry, must be string:string");
    }
}

/* Base method for (re)initializing common elements */
static void StdProfileInit(NGXMGR_Profile *profile, NGXMGR_Profile *template,
                           const char *profileName, WXJSONValue *config) {
    WXJSONValue *extAttr;
    char errMsg[1024];

    /* Template is only provided for true initialization */
    if (template != NULL) {
        /* Copy the source profile details */
        *profile = *template;
        profile->name = profileName;

        /* Pre-initialize the configuration details */
        profile->defaultIndex = NULL;
        profile->sessionIPLocked = FALSE;
        WXDict_Init(&(profile->extAttributes), 0, TRUE);
    }

    /* Bind the configuration data */
    if (!WXJSON_Bind(config, profile, stdBindings, STD_CFG_COUNT,
                     errMsg, sizeof(errMsg))) {
        /* Nothing here is fatal, just error */
        WXLog_Error("Profile configuration binding error: %s", errMsg);
    }

    /* Extended attributes is a bit more convoluted (convert and persist) */
    extAttr = WXJSON_Find(config, "extendedAttributes");
    if (extAttr != NULL) {
        if (extAttr->type != WXJSONVALUE_OBJECT) {
            WXLog_Error("Invalid externalAttributes value, expecting object");
        } else {
            (void) WXHash_Scan(&(extAttr->value.oval),
                               extAttrScanner, &(profile->extAttributes));
        }
    }
}

/* Session allocation callback to complete login sequence */
static void StdSessionEstablishHandler(NGXModuleConnection *conn,
                                       char *sessionId, WXBuffer *attributes,
                                       char *destURL) {
    uint8_t rspBuffer[1024];
    WXBuffer rsp;

    if (destURL == NULL) destURL = "/index.html";
    WXBuffer_InitLocal(&rsp, rspBuffer, sizeof(rspBuffer));
    if ((sessionId == NULL) || 
            (WXBuffer_Pack(&rsp, "na*c", (uint16_t) strlen(destURL),
                           destURL, (uint8_t) 0) == NULL) ||
            (WXBuffer_Append(&rsp, attributes->buffer, attributes->length,
                             TRUE) == NULL)) {
        NGXMGR_IssueErrorResponse(conn, 500, "Internal Session Error",
                                  "Internal error in session allocation");
    } else {
        /* Session establish response with redirect */
        NGXMGR_IssueResponse(conn, NGXMGR_SESSION_ESTABLISH,
                             rsp.buffer, rsp.length);

        /* Note that mem failure can only occur on attribute buffer attach */
        WXBuffer_Destroy(&rsp);
    }
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
    char *assertionConsumerURL;
    char *entityId;
    char *providerName;
    char *destination;
    int forceAuthn;
    int isPassive;
    char *encodedCert;
    int clockSkew;

    /* Derived elements from configuration */
    X509 *idpCertificate;
    WXJSONValue *attributes;
    WXDictionary attrMap;

    /* Other profile-specific data (all accessed in event thread) */
    WXHashTable reqSessions;
} SAMLProfile;

/**
 * Tracking structure for original SAML session request, for response
 * validation (replay) and destination tracking.
 *
 * NOTE (here for lack of anywhere else): the SAML protocol supports
 * the RelayState parameter, which the implementation could use to track
 * the origin of the SAML request.  But to prevent replay attacks, the
 * manager needs to track the details of the original session request, so
 * we store it here.  A future extension could be a configurable set of
 * RelayState mappings for IdP originated sessions...
 */
typedef struct SAMLReqSession {
    char *reqSessionId, *destURL;
    time_t start;
} SAMLReqSession;

/**
 * Configuration binding definitions to parse the above.
 */
static WXJSONBindDefn samlBindings[] = {
    { "signOnURL", WXJSONBIND_STR,
      offsetof(SAMLProfile, signOnURL), TRUE },
    { "idpEntityId", WXJSONBIND_STR,
      offsetof(SAMLProfile, idpEntityId), TRUE },

    { "assertionConsumerURL", WXJSONBIND_STR,
      offsetof(SAMLProfile, assertionConsumerURL), FALSE },
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
      offsetof(SAMLProfile, encodedCert), FALSE },
    { "clockSkew", WXJSONBIND_INT,
      offsetof(SAMLProfile, clockSkew), FALSE },
    { "attributes", WXJSONBIND_REF,
      offsetof(SAMLProfile, attributes), FALSE }
};

#define SAML_CFG_COUNT (sizeof(samlBindings) / sizeof(WXJSONBindDefn))

/* Forward declare for initialization, instance defined at end */
static NGXMGR_Profile SAMLBaseProfile;

/* Default map of SAML assertion attributes for variable keys */
static struct {
    char *uri, *key;
} dfltAttrs[] = {
    /* Note that the URI's are mapping in a case-insensitive manner */
    { "firstname", "givenname" },
    { "givenname", "givenname" },
    { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
          "givenname" },

    { "lastname", "surname" },
    { "surname", "surname" },
    { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
          "surname" },

    { "displayname", "displayname" },
    { "fullname", "displayname" },
    { "http://schemas.microsoft.com/identity/claims/displayname",
          "displayname" },

    { "emailaddress", "emailaddress" },
    { "email", "emailaddress" },
    { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
          "emailaddress" }
};

#define DFLT_ATTR_COUNT (sizeof(dfltAttrs) / sizeof(dfltAttrs[0]))

static int samlAttrScanner(WXHashTable *table, void *key, void *obj,
                           void *userData) {
    WXJSONValue *val = (WXJSONValue *) obj, *aval;
    WXDictionary *attrMap = (WXDictionary *) userData;
    int idx;

    if (val->type == WXJSONVALUE_STRING) {
        if (!WXDict_PutEntry(attrMap, val->value.sval, (char *) key)) {
            WXLog_Error("Memory failure defining attribute map");
        }
    } else if (val->type == WXJSONVALUE_ARRAY) {
        aval = (WXJSONValue *) val->value.aval.array;
        for (idx = 0; idx < val->value.aval.length; aval++, idx++) {
            if (aval->type == WXJSONVALUE_STRING) {
                if (!WXDict_PutEntry(attrMap, aval->value.sval, (char *) key)) {
                    WXLog_Error("Memory failure defining attribute map");
                }
            } else {
                WXLog_Error("Invalid mapping array entry (not string");
            }
        }
    } else {
        WXLog_Error("Invalid attribute definition value (string/array)");
    }

    return 0;
}

/* Standard initialization method for a SAML profile */
static NGXMGR_Profile *SAMLInit(NGXMGR_Profile *orig, const char *profileName,
                                WXJSONValue *config) {
    SAMLProfile *retval = (SAMLProfile *) orig;
    char errMsg[1024];
    BIO *bio;
    size_t l;
    int idx;

    /* First call will not provide a value */
    if (retval == NULL) {
        retval = (SAMLProfile *) WXMalloc(sizeof(SAMLProfile));
        if (retval == NULL) return NULL;

        /* Initialize the baseline profile information */
        StdProfileInit(&(retval->base), &SAMLBaseProfile, profileName, config);

        /* Pre-initialize the configuration details/defaults */
        retval->signOnURL = NULL;
        retval->idpEntityId = NULL;

        retval->assertionConsumerURL = NULL;
        retval->entityId = NULL;
        retval->providerName = NULL;
        retval->destination = NULL;
        retval->forceAuthn = FALSE;
        retval->isPassive = FALSE;
        retval->encodedCert = FALSE;
        retval->clockSkew = 0;

        retval->attributes = NULL;
        retval->idpCertificate = NULL;
        if ((!WXDict_Init(&(retval->attrMap), 64, FALSE)) ||
                (!WXHash_InitTable(&(retval->reqSessions), 64))) {
            WXLog_Error("Memory failure allocating mapping content");
            WXFree(retval);
            return NULL;
        }
    } else {
        /* Update base configuration */
        StdProfileInit(orig, NULL, NULL, config);
    }

    /* Bind the configuration data */
    if (!WXJSON_Bind(config, retval, samlBindings, SAML_CFG_COUNT,
                     errMsg, sizeof(errMsg))) {
        /* Possibly memory leak here, turning a blind eye... */
        WXLog_Error("SAML configuration binding error: %s", errMsg);
        return NULL;
    }

    /* Translate the attribute mappings */
    WXDict_Empty(&(retval->attrMap));
    for (idx = 0; idx < DFLT_ATTR_COUNT; idx++) {
        if (!WXDict_PutEntry(&(retval->attrMap), dfltAttrs[idx].uri,
                             dfltAttrs[idx].key)) {
            WXLog_Error("Memory failure defining attributes");
            return NULL;
        }
    }
    if (retval->attributes != NULL) {
        if (retval->attributes->type != WXJSONVALUE_OBJECT) {
            WXLog_Error("Attributes configuration must be a JSON object/map");
        } else {
            (void) WXHash_Scan(&(retval->attributes->value.oval),
                               samlAttrScanner, &(retval->attrMap));
        }
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
                              char *sourceIpAddr, char *request) {
    char *url, *enc, *sessReqId, xmlBuff[1024], *deflateBuff, tmBuff[64];
    SAMLProfile *profile = (SAMLProfile *) prf;
    WXMLNamespace *samlNs, *samlpNs, authNs;
    WXMLElement *authnReqElmnt = NULL;
    BIO *base64Enc = NULL, *base64Buff;
    SAMLReqSession *reqSession = NULL;
    z_stream deflateStrm;
    WXBuffer buffer;
    BUF_MEM *bptr;
    time_t now;
    int zrc;

    /* Initialize this up front for cleanup */
    WXBuffer_InitLocal(&buffer, xmlBuff, sizeof(xmlBuff));

    /* Allocate and record a pending session instance */
    /* Note: this is transient and signed, so doesn't need excessive length? */
    sessReqId = NGXMGR_GenerateSessionId(24);
    if (sessReqId == NULL) goto memfail;
    reqSession = (SAMLReqSession *) WXMalloc(sizeof(SAMLReqSession));
    if (reqSession == NULL) {
        WXFree(sessReqId);
        goto memfail;
    }
    reqSession->reqSessionId = sessReqId;
    reqSession->start = time((time_t *) NULL);
    if (strncmp(request, "GET ", 4) == 0) {
        reqSession->destURL = (char *) WXMalloc(strlen(request) + 1);
        if (reqSession->destURL == NULL) goto memfail;
        (void) strcpy(reqSession->destURL, request + 4);
    } else {
        /* Fall back to the conifigured default index */
    }
    if (!WXHash_PutEntry(&(profile->reqSessions), sessReqId, reqSession,
                         NULL, NULL, WXHash_StrHashFn, WXHash_StrEqualsFn)) {
        goto memfail;
    }

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
    if (WXML_AllocateAttribute(authnReqElmnt, "ID", NULL, sessReqId, 
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
    if (reqSession != NULL) {
        (void) WXHash_RemoveEntry(&(profile->reqSessions),
                                  reqSession->reqSessionId, NULL, NULL,
                                  WXHash_StrHashFn, WXHash_StrEqualsFn);
        if (reqSession->destURL != NULL) WXFree(reqSession->destURL);
        WXFree(reqSession->reqSessionId);
        WXFree(reqSession);
    }
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

/* Standard algorithm for converting civil/Gregorian date to days since epoch */
static int daysFromCivil(int y, int m, int d) {
    y -= (m <= 2) ? 1 : 0;
    int era = ((y >= 0) ? y : (y - 399)) / 400;
    int yoe = y - era * 400;
    int doy = (153 * (m + ((m > 2) ? -3 : 9)) + 2) / 5 + d - 1;
    int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

/* Parse the round-trip formatted timestamp into epoch time */
static time_t parseRTT(char *which, char *tmstr) {
    int dfc;

    /* Only light validation, presume IdP is well behaved */
    if ((strlen(tmstr) < 20) ||
            (tmstr[4] != '-') || (tmstr[7] != '-') || (tmstr[10] != 'T') ||
            (tmstr[13] != ':') || (tmstr[16] != ':') ||
            (tmstr[strlen(tmstr) - 1] != 'Z')) {
        WXLog_Warn("Invalid format for %s - '%s'", which, tmstr);
        return 0;
    }

    dfc = daysFromCivil(atoi(tmstr), atoi(tmstr + 5), atoi(tmstr + 8));
    return 60 * (60 * (24L * dfc + atoi(tmstr + 11)) + atoi(tmstr + 14)) +
           atoi(tmstr + 17);
}

/* Asynchronous data carrier and method for database verification */
typedef struct {
    NGXMGR_Profile *prf;
    NGXModuleConnection *conn;
    char sourceIpAddr[64];
    char *destURL;
    WXDictionary attributes;

    /* Local processing objects for verify generation and handling */
    WXBuffer cmdbuff;
    WXArray extAttrKeys;
} SAMLLoginInfo;

int extAttrFieldCB(WXHashTable *table, void *key, void *obj, void *userData) {
    SAMLLoginInfo *info = (SAMLLoginInfo *) userData;
    char *field = (char *) key;

    if ((WXBuffer_Append(&(info->cmdbuff), ", ", 2, TRUE) == NULL) ||
            (WXBuffer_Append(&(info->cmdbuff), field, strlen(field),
                             TRUE) == NULL)) {
        return 1;
    }
    if (WXArray_Push(&(info->extAttrKeys), &obj) == NULL) return 1;

    return 0;
}

static void *samlLoginFinish(void *arg) {
    SAMLLoginInfo *info = (SAMLLoginInfo *) arg;
    WXBuffer *cmdbuff = &(info->cmdbuff);
    WXDBConnection *dbconn = NULL;
    WXDBResultSet *rs = NULL;
    int userId, idx;
    char *uid, *val;

    /* Query to extract the userId and extended attributes */
    if (WXBuffer_Init(cmdbuff, 1024) == NULL) goto memfail;
    if (WXArray_Init(&(info->extAttrKeys), char *, 16) == NULL) goto memfail;
    (void) WXBuffer_Append(cmdbuff, "SELECT user_id", 14, TRUE);
    if (WXHash_Scan(&(info->prf->extAttributes.base),
                    extAttrFieldCB, info) != 0) goto memfail;
    if (WXBuffer_Append(cmdbuff,
                        " FROM ngxsessionmgr.users"
                        " WHERE active = 't' AND external_auth_id = '",
                        25 + 44, TRUE) == NULL) goto memfail;
    uid = (char *) WXDict_GetEntry(&(info->attributes), "uid");
    while (*uid != '\0') {
        if (*uid == '\'') {
            if (WXBuffer_Append(cmdbuff, "\\", 1, TRUE) == NULL) goto memfail;
        }
        if (WXBuffer_Append(cmdbuff, uid, 1, TRUE) == NULL) goto memfail;
        uid++;
    }
    if (WXBuffer_Append(cmdbuff, "'\0", 2, TRUE) == NULL) goto memfail;

    /* Issue query and validate/extract user information */
    dbconn = WXDBConnectionPool_Obtain(GlobalData.dbConnPool);
    if (dbconn == NULL) {
        WXLog_Error("Failed to obtain connection for user verification");
        goto verifyfail;
    }

    rs = WXDBConnection_ExecuteQuery(dbconn, cmdbuff->buffer);
    if (rs == NULL) {
       WXLog_Error("Unexpected error validating user information: %s",
                    WXDB_GetLastErrorMessage(dbconn));
       goto verifyfail;
    }

    /* Presumes exactly one row, read first only */
    if (!WXDBResultSet_NextRow(rs)) {
        WXLog_Error("SAML authenticated identity '%s' but not defined/active",
                    (char *) WXDict_GetEntry(&(info->attributes), "uid"));
        NGXMGR_IssueErrorResponse(info->conn, 403, "Invalid User",
                           "User externally validated but not defined/active");
        goto cleanup;
    }

    /* Woohoo!  User validated, extract associated attributes */
    userId = atol(WXDBResultSet_ColumnData(rs, 0));
    for (idx = 0; idx < info->extAttrKeys.length; idx++) {
        if (!WXDBResultSet_ColumnIsNull(rs, idx + 1)) {
            if (!WXDict_PutEntry(&(info->attributes),
                                 ((char **)info->extAttrKeys.array)[idx],
                                 WXDBResultSet_ColumnData(rs, idx + 1))) {
                goto memfail;
            }
        }
    }

    /* And issue the session instance */
    NGXMGR_AllocateNewSession(userId, info->sourceIpAddr, -1,
                              &(info->attributes),
                              (info->destURL != NULL) ? info->destURL :
                                                        info->prf->defaultIndex,
                              info->conn, StdSessionEstablishHandler);

cleanup:
    if (rs != NULL) WXDBResultSet_Close(rs);
    if (dbconn != NULL) WXDBConnectionPool_Return(dbconn);
    WXArray_Destroy(&(info->extAttrKeys));
    WXBuffer_Destroy(&(info->cmdbuff));
    if (info->destURL != NULL) WXFree(info->destURL);
    WXDict_Destroy(&(info->attributes));
    WXFree(info);
    return NULL;

memfail:
    WXLog_Error("Memory allocation failure in SAML login completion");
    NGXMGR_IssueErrorResponse(info->conn, 500, "Memory Error",
                       "Internal Error: Manager memory allocation error");
    goto cleanup;

verifyfail:
    NGXMGR_IssueErrorResponse(info->conn, 403, "User Verify Error",
                       "Internal Error: Unable to verify user information");
    goto cleanup;
}

/* Process SAML commands, establish login completion or logout */
static void SAMLLogin(NGXMGR_Profile *prf, NGXModuleConnection *conn,
                      char *sourceIpAddr, char *data, int dataLen) {
    WXMLElement *root = NULL, *node, *chld, *prnt, *conf, *val, *attrs, *attv;
    char *ptr, *samlResp, *decSamlResp = NULL, errorMsg[1024], *nameId;
    WXMLLinkedElement *signedRefs = NULL, *sref;
    SAMLProfile *profile = (SAMLProfile *) prf;
    BIO *base64Dec, *base64Buff = NULL;
    SAMLReqSession *reqSession;
    WXDictionary attributes;
    WXHashTable postData;
    char *destURL = NULL;
    WXMLAttribute *attr;
    SAMLLoginInfo *info;
    const char *key;
    time_t tm;
    int len;

    /* Decode the form arguments */
    attributes.base.entries = NULL;
    if ((!WXHash_InitTable(&postData, 16)) ||
            (!parseFormEncoded(&postData, data, dataLen))) goto memfail;

    /* Pull the saml response, prep for decoding */
    samlResp = WXHash_GetEntry(&postData, "SAMLResponse",
                               WXHash_StrHashFn, WXHash_StrEqualsFn);
    if (samlResp == NULL) {
        NGXMGR_IssueErrorResponse(conn, 500, "Invalid SAML Response",
                          "Verify response missing SAMLResponse data element");
        freeEncodedData(&postData);
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
        freeEncodedData(&postData);
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
            goto samlerr;
        }
    }

    /* Prepare for session attribute collection */
    if (!WXDict_Init(&attributes, 16, FALSE)) goto memfail;

    /* Validations of response assertions according to SAML spec 4.1.4.2/3 */
    nameId = NULL;
    for (node = root->children; node != NULL; node = node->next) {
        /* Just interested in assertions */
        if ((node->name == NULL) ||
                   (strcmp(node->name, "Assertion") != 0)) continue;

        /* If signature verification enabled, assertion must be signed */
        if (signedRefs != NULL) {
            prnt = node;
            while (prnt != NULL) {
                sref = signedRefs;
                while (sref != NULL) {
                    if (sref->elmnt == prnt) break;
                    sref = sref->nextElmnt;
                }
                if (sref != NULL) break;
                prnt = prnt->parent;
            }

            if (prnt == NULL) {
                WXLog_Warn("Unsigned Assertion found, skipping");
                continue;
            }
        }

        /* Per XSD, Assertion must contain Issuer response to entity */
        if ((chld = WXML_Find(node, "/Issuer", FALSE)) == NULL) {
            WXLog_Error("Assertion missing Issuer child element");
            goto samlerr;
        }
        attr = WXML_Find(node, "@Format", FALSE);
        if (attr != NULL) {
            if ((attr->value == NULL) ||
                (strcmp(attr->value,
                    "urn:oasis:names:tc:SAML:2.0:nameid-format:entity") != 0)) {
                WXLog_Error("Incorrect Issuer Format '%s'", attr->value);
                goto samlerr;
            }
        }
        if ((chld->content == NULL) ||
                (strcmp(chld->content, profile->idpEntityId) != 0)) {
            WXLog_Warn("Assertion for mismatched entity, skipping");
            continue;
        }

        /* Find valid Authn->Subject(Confirmation) relation */
        /* Lots of specific dependencies from 4.1.4.2/4.1.4.3 here */
        if ((chld = WXML_Find(node, "/AuthnStatement", FALSE)) != NULL) {
            /* Only consume valid bearer Subject instances */
            /* This does assume there is only one marked instance */
            if (((attr = WXML_Find(node, "/Subject/SubjectConfirmation/@Method",
                                   FALSE)) != NULL) &&
                    (attr->value != NULL) &&
                    (strcmp(attr->value,
                            "urn:oasis:names:tc:SAML:2.0:cm:bearer") == 0)) {
                conf = WXML_Find(attr->element, "/SubjectConfirmationData",
                                 FALSE);
            }
        }
        if ((conf != NULL) &&
                (((attr = WXML_Find(conf, "/@Recipient", FALSE)) == NULL) ||
                     (attr->value == NULL))) {
            WXLog_Warn("Assertion Subject missing Recipient, skipping");
            conf = NULL;
        }
        if (conf != NULL) {
            /* Only validate the acu if it is actually configured */
            if (profile->assertionConsumerURL != NULL) {
                if (strcmp(attr->value, profile->assertionConsumerURL) != 0) {
                    WXLog_Warn("Assertion Subject Recipient mismatch "
                               "('%s' vs. '%s'), skipping",
                               attr->value, profile->assertionConsumerURL);
                    conf = NULL;
                }
            }
        }
        if ((conf != NULL) &&
                (((attr = WXML_Find(conf, "/@NotOnOrAfter", FALSE)) == NULL) ||
                     (attr->value == NULL))) {
            WXLog_Warn("Assertion Subject missing NotOnOrAfter, skipping");
            conf = NULL;
        } else {
            tm = parseRTT("NotOnOrAfter", attr->value);
            if (tm == 0) {
                conf = NULL;
            } else if (tm < (time((time_t *) NULL) - profile->clockSkew)) {
                WXLog_Warn("Assertion NotOnOrAfter in past (%d s), skipping",
                           (int) (time((time_t *) NULL) - tm));
                conf = NULL;
            }
        }
        if ((conf != NULL) &&
                (((attr = WXML_Find(conf, "/@InResponseTo", FALSE)) == NULL) ||
                     (attr->value == NULL))) {
            WXLog_Warn("Assertion Subject missing InResponseTo, skipping");
            conf = NULL;
        } else {
            reqSession = WXHash_GetEntry(&(profile->reqSessions), attr->value,
                                         WXHash_StrHashFn, WXHash_StrEqualsFn);
            if (reqSession == NULL) {
                WXLog_Warn("Unsolicited or replay Assertion, skipping");
                conf = NULL;
            } else {
                (void) WXHash_RemoveEntry(&(profile->reqSessions), attr->value,
                                          NULL, NULL, WXHash_StrHashFn,
                                          WXHash_StrEqualsFn);
                /* Steal the destination for use in the redirect */
                destURL = reqSession->destURL;  reqSession->destURL = NULL;
                WXFree(reqSession->reqSessionId);
                WXFree(reqSession);
            }
        }
        if ((conf != NULL) &&
                (((val = WXML_Find(node,
                                   "/Conditions/AudienceRestriction/Audience",
                                   FALSE)) == NULL) ||
                     (val->content == NULL))) {
            WXLog_Warn("Assertion missing Audience, skipping");
            conf = NULL;
        } else if ((conf != NULL) && (profile->entityId != NULL)) {
            if (strcmp(val->content, profile->entityId) != 0) {
                WXLog_Warn("Assertion Audience/EntityId mismatch "
                           "('%s' vs '%s'), skipping", val->content,
                           profile->entityId);
                conf = NULL;
            }
        }
        /* Other Conditions do not have to be honoured, for now we don't */

        /* If we've passed the validations, extract the nameid */
        /* Poorly behaving IdP could mess with multiples, oh well */
        if ((conf != NULL) &&
                ((val = WXML_Find(conf->parent->parent,
                                  "/NameID", FALSE)) != NULL) &&
                (val->content != NULL)) {
            nameId = val->content;
            WXLog_Debug("Validated principal assertion for '%s'", nameId);

            /* TODO - grab the optional elements as well */
            /* AuthnStatement/@SessionIndex */
            /* AuthnStatement/@SessionNotOnOrAfter */
        }

        /* Regardless of identity conditions, attributes can be distributed */
        if ((attrs = WXML_Find(node, "/AttributeStatement", FALSE)) != NULL) {
            for (chld = attrs->children; chld != NULL; chld = chld->next) {
                if ((chld->name == NULL) ||
                        (strcmp(chld->name, "Attribute") != 0)) continue;

                if (((attr = WXML_Find(chld, "/@Name", FALSE)) == NULL) ||
                        (attr->value == NULL)) continue;
                if (((attv = WXML_Find(chld, "/AttributeValue",
                                       FALSE)) == NULL) ||
                        (attv->content == NULL)) continue;

                /* Only consume recognized attribute instances */
                key = WXDict_GetEntry(&(profile->attrMap), attr->value);
                if (key == NULL) continue;
                if (!WXDict_PutEntry(&attributes, key, attv->content)) {
                    goto memfail;
                }
            }
        }
    }

    /* Final test, one of the Assertions must have validated user identity */
    if (nameId == NULL) {
        NGXMGR_IssueErrorResponse(conn, 400, "Improper SAML Response",
                                  "One or more signature/validation errors in "
                                  "SAML response, unable to validate user "
                                  "identity");
    } else {
        /* Populate the uid unless already provided (swap) */
        if ((ptr = (char *) WXDict_GetEntry(&attributes, "uid")) == NULL) {
            if (!WXDict_PutEntry(&attributes, "uid", nameId)) goto memfail;
        } else {
            nameId = ptr;
        }

        /* DB dependent, immediately assign session or validate uid */
        /* TODO - handle externally specified expiry time */
        if (GlobalData.dbConnPool == NULL) {
            NGXMGR_AllocateNewSession(-1, sourceIpAddr, -1, &attributes,
                                      (destURL != NULL) ? destURL :
                                                          prf->defaultIndex,
                                      conn, StdSessionEstablishHandler);
        } else {
            /* Hand off to the worker process for database interaction */
            info = (SAMLLoginInfo *) WXCalloc(sizeof(SAMLLoginInfo));
            if (info == NULL) goto memfail;
            info->prf = prf;
            info->conn = conn;
            (void) strcpy(info->sourceIpAddr, sourceIpAddr);
            info->destURL = destURL;
            info->attributes = attributes;

            if (WXThreadPool_Enqueue(GlobalData.workerThreadPool,
                                     samlLoginFinish, info) < 0) {
                WXLog_Error("Failed to issue worker for login completion");
                WXFree(info);
            } else {
                /* Nullify to prevent cleanup mucking up handoff */
                destURL = NULL;
                (void) memset(&attributes, 0, sizeof(WXDictionary));
            }
        }
    }

    /* Cleanup */
    if (destURL != NULL) WXFree(destURL);
    if (attributes.base.entries != NULL) WXDict_Destroy(&attributes);
    if (signedRefs != NULL) WXML_FreeLinkedElements(signedRefs);
    freeEncodedData(&postData);
    WXML_Destroy(root);

    return;

samlerr:
    if (destURL != NULL) WXFree(destURL);
    if (attributes.base.entries != NULL) WXDict_Destroy(&attributes);
    if (signedRefs != NULL) WXML_FreeLinkedElements(signedRefs);
    freeEncodedData(&postData);
    WXML_Destroy(root);
    NGXMGR_IssueErrorResponse(conn, 401, "Unauthorized (SAML)",
                        "Invalid signed SAML response or error in processing");
    return;

memfail:
    WXLog_Error("Memory allocation failure in SAML response processing");
    if (destURL != NULL) WXFree(destURL);
    if (attributes.base.entries != NULL) WXDict_Destroy(&attributes);
    if (postData.entries != NULL) freeEncodedData(&postData);
    if (base64Buff != NULL) BIO_free_all(base64Buff);
    if (decSamlResp != NULL) WXFree(decSamlResp);
    if (root != NULL) WXML_Destroy(root);
    NGXMGR_IssueErrorResponse(conn, 500, "Memory Error",
                       "Internal Error: Manager memory allocation error");
}

static void SAMLProcessAction(NGXMGR_Profile *prof, NGXModuleConnection *conn,
                              char *sourceIpAddr, char *request, char *action,
                              char *sessionId, char *data, int dataLen) {
    if ((strcmp(action, "login") == 0) && (strncmp(request, "PST", 3) == 0)) {
        SAMLLogin(prof, conn, sourceIpAddr, data, dataLen);
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
