/**
 * Containers for processing the various manager security profiles/config.
 * 
 * Copyright (C) 2018-2026 J.M. Heisz.  All Rights Reserved.
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
#include "thread.h"

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
            if (h >= 'a') h = h - 'a' + 10;
            else if (h >= 'A') h = h - 'A' + 10;
            else h = h - '0';

            if (l >= 'a') l = l - 'a' + 10;
            else if (l >= 'A') l = l - 'A' + 10;
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
        /* Find next separator, bounded by (remaining) length */
        str = ptr;
        l = len;
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

    return 0;
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
    int isExtAuthOnly;
    int debugReqResp;
    int insecureNoSignature;

    /* Derived elements from configuration */
    X509 *idpCertificate;
    WXJSONValue *attributes;
    WXDictionary attrMap;

    /* Pending request tracking, shared across fibers (watch lock/yield) */
    WXHashTable reqSessions;
    WXThread_Mutex reqLock;
} SAMLProfile;

/* Pending/incomplete authentication requests timeout (seconds) */
#define SAML_REQUEST_LIFESPAN 900

/* Restrict destination length to avoid protocol overflow */
#define SAML_MAX_DEST_URL 8192

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
      offsetof(SAMLProfile, attributes), FALSE },
    { "isExternalAuthOnly", WXJSONBIND_BOOLEAN,
      offsetof(SAMLProfile, isExtAuthOnly), FALSE },
    { "debugReqResp", WXJSONBIND_BOOLEAN,
      offsetof(SAMLProfile, debugReqResp), FALSE },
    { "insecureNoSignature", WXJSONBIND_BOOLEAN,
      offsetof(SAMLProfile, insecureNoSignature), FALSE }
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

/* Handy for debugging */
static void logXML(WXMLElement *root) {
    WXBuffer buffer;

    WXBuffer_Init(&buffer, 1024);
    WXML_Encode(&buffer, root, TRUE);
    WXLog_Debug("XML:\n%s", buffer.buffer);
    WXBuffer_Destroy(&buffer);
}

/*
 * Create a safe/sanitized destination URL for use in the SSO negotiation.
 * URI encodes as needed and ensures absolute paths.  Returns NULL (fallback
 * to the default endpoint) for memfail or invalid content.
 *
 * NOTE: similar to, but not exactly same as version in toolkit
 */
static char *safeDestURL(char *uri) {
    static char hex[] = "0123456789ABCDEF";
    uint8_t ch, *src = (uint8_t *) uri;
    char *retval, *dst;

    /* Only allow standard absolute paths */
    if ((*src != '/') || (src[1] == '/') || (src[1] == '\\')) return NULL;

    /* Assume worst case of encoding all characters */
    retval = (char *) WXMalloc(3 * strlen(uri) + 1);
    if (retval == NULL) return NULL;

    dst = retval;
    while ((ch = *src) != '\0') {
        /* Encode just illegal characters, assume proper inner encoding */
        if ((ch <= 0x20) || (ch >= 0x7F) || (ch == '"') || (ch == '\\')) {
            *(dst++) = '%';
            *(dst++) = hex[(ch >> 4) & 0x0F];
            *(dst++) = hex[ch & 0x0F];
        } else {
            *(dst++) = ch;
        }
        src++;
    }
    *dst = '\0';

    if ((dst - retval) > SAML_MAX_DEST_URL) {
        WXLog_Warn("Destination redirect length exceeded, using default");
        WXFree(retval);
        return NULL;
    }

    return retval;
}

/* Scanner to create list of outstanding session requests that have expired */
static int expireScanCB(WXHashTable *table, void *key, void *obj,
                        void *userData) {
    SAMLReqSession *reqSession = (SAMLReqSession *) obj;
    WXArray *expired = (WXArray *) userData;

    if ((time((time_t *) NULL) - reqSession->start) > SAML_REQUEST_LIFESPAN) {
        if (WXArray_Push(expired, &reqSession) == NULL) return 1;
    }

    return 0;
}

/* Discard expired pending requests, must be called under the request lock */
static void expireReqSessions(SAMLProfile *profile) {
    SAMLReqSession *reqSession;
    WXArray expired;
    int idx;

    /* Generate the list of expired sessions using the scanner callback */
    if (WXArray_Init(&expired, SAMLReqSession *, 16) == NULL) return;
    (void) WXHash_Scan(&(profile->reqSessions), expireScanCB, &expired);

    /* And purge them from the pending hash */
    for (idx = 0; idx < expired.length; idx++) {
        reqSession = ((SAMLReqSession **) expired.array)[idx];
        (void) WXHash_RemoveEntry(&(profile->reqSessions),
                                  reqSession->reqSessionId, NULL, NULL,
                                  WXHash_StrHashFn, WXHash_StrEqualsFn);
        if (reqSession->destURL != NULL) WXFree(reqSession->destURL);
        WXFree(reqSession->reqSessionId);
        WXFree(reqSession);
    }
    WXArray_Destroy(&expired);
}

/* Standard initialization method for a SAML profile */
static NGXMGR_Profile *SAMLInit(NGXMGR_Profile *orig, const char *profileName,
                                WXJSONValue *config) {
    SAMLProfile *retval = (SAMLProfile *) orig;
    char errMsg[1024];
    X509 *cert;
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
        retval->isExtAuthOnly = FALSE;
        retval->debugReqResp = FALSE;
        retval->insecureNoSignature = FALSE;

        retval->attributes = NULL;
        retval->idpCertificate = NULL;
        if ((!WXDict_Init(&(retval->attrMap), 64, FALSE)) ||
                (!WXHash_InitTable(&(retval->reqSessions), 64))) {
            WXLog_Error("Memory failure allocating mapping content");
            WXFree(retval);
            return NULL;
        }
        if (WXThread_MutexInit(&(retval->reqLock), FALSE) != WXTRC_OK) {
            WXLog_Error("Failed to initialize SAML request tracking lock");
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

        /* Reference into the config tree, released after load */
        retval->attributes = NULL;
    }

    /* Post-process the validation certificate, if provided (on success) */
    if ((retval->encodedCert != NULL) &&
            ((l = strlen(retval->encodedCert)) != 0)) {
        bio = BIO_new(BIO_s_mem());
        if ((bio == NULL) || (BIO_write(bio, retval->encodedCert, l) != l)) {
            WXLog_Error("Memory failure allocating certificate content");
            if (bio != NULL) BIO_free_all(bio);
            return NULL;
        }

        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free_all(bio);
        if (cert == NULL) {
            WXLog_Error("Failed to parse X509 PEM encoded certificate");
            return NULL;
        }
        if (retval->idpCertificate != NULL) {
            X509_free(retval->idpCertificate);
        }
        retval->idpCertificate = cert;

        WXLog_Debug("Loaded IdP Certificate for %s",
                    X509_NAME_oneline(X509_get_subject_name(
                                               retval->idpCertificate),
                                      errMsg, sizeof(errMsg)));
    } else {
        if (retval->idpCertificate != NULL) {
            X509_free(retval->idpCertificate);
            retval->idpCertificate = NULL;
        }

        if (retval->insecureNoSignature) {
            WXLog_Warn("\n\nWARNING: No IdP validation certificate provided!\n"
              "This exposes your SAML SP to injection replay attacks, and\n"
              "should ONLY be enabled under emergency conditions where the\n"
              "validation code is failing unexpectedly (and maybe not even\n"
              "then).\n");
        } else {
            WXLog_Error("No IdP validation certificate provided for SAML "
                        "profile '%s', all logins will be rejected.",
                        retval->base.name);
        }
    }

    return &(retval->base);
}

/* Verify processing method for the SAML profile, establish new session */
static void SAMLProcessVerify(NGXMGR_Profile *prf, NGXModuleConnection *conn,
                              char *sourceIpAddr, char *request) {
    char *url, *enc, *sessReqId, tmBuff[64], xmlBuff[1024], *deflateBuff = NULL;
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
    reqSession->destURL = NULL;
    reqSession->start = time((time_t *) NULL);
    if (strncmp(request, "GET ", 4) == 0) {
        /* Rejection here also NULLs back to default index */
        reqSession->destURL = safeDestURL(request + 4);
    } else {
        /* Fall back to the configured default index */
    }
    (void) WXThread_MutexLock(&(profile->reqLock));
    expireReqSessions(profile);
    if (!WXHash_PutEntry(&(profile->reqSessions), sessReqId, reqSession,
                         NULL, NULL, WXHash_StrHashFn, WXHash_StrEqualsFn)) {
        (void) WXThread_MutexUnlock(&(profile->reqLock));
        if (reqSession->destURL != NULL) WXFree(reqSession->destURL);
        WXFree(reqSession->reqSessionId);
        WXFree(reqSession);
        reqSession = NULL;
        goto memfail;
    }
    (void) WXThread_MutexUnlock(&(profile->reqLock));

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

    /* Sometimes you just have to look closer */
    if (profile->debugReqResp) logXML(authnReqElmnt);

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
        WXFree(deflateBuff);
        WXBuffer_Destroy(&buffer);
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
        (void) WXThread_MutexLock(&(profile->reqLock));
        (void) WXHash_RemoveEntry(&(profile->reqSessions),
                                  reqSession->reqSessionId, NULL, NULL,
                                  WXHash_StrHashFn, WXHash_StrEqualsFn);
        (void) WXThread_MutexUnlock(&(profile->reqLock));
        if (reqSession->destURL != NULL) WXFree(reqSession->destURL);
        WXFree(reqSession->reqSessionId);
        WXFree(reqSession);
    }
    WXLog_Error("Memory allocation failure!");
    NGXMGR_IssueErrorResponse(conn, 500, "Memory Error",
                       "Internal Error: Manager memory allocation error");
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

/* Validate time limits (with skew) for the provided element */
static int validateTimeWindow(WXMLElement *elmnt, char *which, int clockSkew,
                              int expiryRequired) {
    time_t tm, now = time((time_t *) NULL);
    WXMLAttribute *attr;

    attr = (WXMLAttribute *) WXML_Find(elmnt, "@NotOnOrAfter", FALSE);
    if ((attr == NULL) || (attr->value == NULL)) {
        if (expiryRequired) {
            WXLog_Warn("Assertion %s missing NotOnOrAfter, skipping", which);
            return FALSE;
        }
    } else {
        tm = parseRTT("NotOnOrAfter", attr->value);
        if (tm == 0) return FALSE;
        if (tm <= (now - clockSkew)) {
            WXLog_Warn("Assertion %s NotOnOrAfter in past (%d s), skipping",
                       which, (int) (now - tm));
            return FALSE;
        }
    }

    attr = (WXMLAttribute *) WXML_Find(elmnt, "@NotBefore", FALSE);
    if ((attr != NULL) && (attr->value != NULL)) {
        tm = parseRTT("NotBefore", attr->value);
        if (tm == 0) return FALSE;
        if (tm > (now + clockSkew)) {
            WXLog_Warn("Assertion %s NotBefore in future (%d s), skipping",
                       which, (int) (tm - now));
            return FALSE;
        }
    }

    return TRUE;
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

static void samlLoginFinish(SAMLLoginInfo *info) {
    WXBuffer *cmdbuff = &(info->cmdbuff);
    WXDBConnection *dbconn = NULL;
    WXDBStatement *stmt = NULL;
    WXDBResultSet *rs = NULL;
    int userId, idx;
    char *uid;

    /* Query to extract the userId and extended attributes */
    uid = (char *) WXDict_GetEntry(&(info->attributes), "uid");
    if (WXBuffer_Init(cmdbuff, 1024) == NULL) goto memfail;
    if (WXArray_Init(&(info->extAttrKeys), char *, 16) == NULL) goto memfail;
    (void) WXBuffer_Append(cmdbuff, "SELECT user_id", 14, TRUE);
    if (WXHash_Scan(&(info->prf->extAttributes.base),
                    extAttrFieldCB, info) != 0) goto memfail;

    /* Identity referenced via bound parameter */
    if (WXBuffer_Append(cmdbuff,
                        " FROM ngxsessionmgr.users"
                        " WHERE active = 't' AND external_auth_id = ?",
                        25 + 44, TRUE) == NULL) goto memfail;
    if (WXBuffer_Append(cmdbuff, "\0", 1, TRUE) == NULL) goto memfail;

    /* Issue query and validate/extract user information */
    dbconn = NGXMGR_ObtainDBConnection();
    if (dbconn == NULL) {
        WXLog_Error("Failed to obtain connection for user verification");
        goto verifyfail;
    }

    stmt = WXDBConnection_Prepare(dbconn, (char *) cmdbuff->buffer);
    if ((stmt == NULL) ||
            (WXDBStatement_BindString(stmt, 0, uid) != WXDRC_OK) ||
            ((rs = WXDBStatement_ExecuteQuery(stmt)) == NULL)) {
       WXLog_Error("Unexpected error validating user information: %s",
                    WXDB_GetLastErrorMessage(dbconn));
       goto verifyfail;
    }

    /* Presumes exactly one row, read first only */
    if (!WXDBResultSet_NextRow(rs)) {
        WXLog_Error("SAML authenticated identity '%s' but not "
                    "defined/active", uid);
        NGXMGR_SessionLog("[%s] SAML login rejected for '%s': identity not "
                          "defined/active", info->sourceIpAddr, uid);
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

    /* Release before allocating, which needs a (capped) connection too */
    WXDBResultSet_Close(rs);
    rs = NULL;
    WXDBStatement_Close(stmt);
    stmt = NULL;
    NGXMGR_ReturnDBConnection(dbconn);
    dbconn = NULL;

    /* And issue the session instance (extended attributes may replace uid) */
    uid = (char *) WXDict_GetEntry(&(info->attributes), "uid");
    NGXMGR_SessionLog("[%s] SAML login accepted for '%s'",
                      info->sourceIpAddr, uid);
    NGXMGR_AllocateNewSession(userId, info->sourceIpAddr, -1,
                              &(info->attributes),
                              (info->destURL != NULL) ? info->destURL :
                                                        info->prf->defaultIndex,
                              info->conn, StdSessionEstablishHandler);

cleanup:
    if (rs != NULL) WXDBResultSet_Close(rs);
    if (stmt != NULL) WXDBStatement_Close(stmt);
    if (dbconn != NULL) NGXMGR_ReturnDBConnection(dbconn);
    WXArray_Destroy(&(info->extAttrKeys));
    WXBuffer_Destroy(&(info->cmdbuff));
    if (info->destURL != NULL) WXFree(info->destURL);
    WXDict_Destroy(&(info->attributes));
    WXFree(info);
    return;

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
    char *reason = "processing error", *respInResponseTo;
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
    BIO_free_all(base64Buff); base64Buff = NULL;
    if (len <= 0) {
        WXLog_Error("Invalid base64 encoding of SAML response");
        NGXMGR_IssueErrorResponse(conn, 400, "Invalid SAML Response",
                                  "Unable to decode content of SAML response");
        WXFree(decSamlResp);
        freeEncodedData(&postData);
        return;
    }
    decSamlResp[len] = '\0';

    root = WXML_Decode(decSamlResp, TRUE, errorMsg, sizeof(errorMsg));
    WXFree(decSamlResp); decSamlResp = NULL;
    if (root == NULL) {
        WXLog_Error("Invalid SAML XML response: %s", errorMsg);
        NGXMGR_IssueErrorResponse(conn, 400, "Invalid SAML Response",
                          "Unable to parse XML content of SAML response");
        freeEncodedData(&postData);
        return;
    }

    /* Sometimes you just have to look closer */
    if (profile->debugReqResp) logXML(root);

    /* Signature validation is mandatory unless explicitly waived */
    if (profile->idpCertificate != NULL) {
        signedRefs = WXML_ValidateSignedReferences(root,
                                  X509_get0_pubkey(profile->idpCertificate));
        if (signedRefs == NULL) {
            /* Either internal error or bad signatures, invalid response */
            reason = "no valid signature";
            goto samlerr;
        }
    } else if (!profile->insecureNoSignature) {
        WXLog_Error("No IdP certificate for SAML profile, rejecting");
        reason = "no IdP certificate configured";
        goto samlerr;
    }

    /* Response level validations (core 3.2.2, profiles 4.1.4.3) */
    attr = (WXMLAttribute *) WXML_Find(root, "/Status/StatusCode/@Value",
                                       FALSE);
    if ((attr == NULL) || (attr->value == NULL) ||
            (strcmp(attr->value,
                    "urn:oasis:names:tc:SAML:2.0:status:Success") != 0)) {
        WXLog_Warn("SAML response status is not success: %s",
                   (((attr == NULL) || (attr->value == NULL)) ? "missing" :
                                                                attr->value));
        reason = "response status not success";
        goto samlerr;
    }
    attr = (WXMLAttribute *) WXML_Find(root, "@Destination", FALSE);
    if ((attr != NULL) && (attr->value != NULL) &&
            (profile->assertionConsumerURL != NULL) &&
            (strcmp(attr->value, profile->assertionConsumerURL) != 0)) {
        WXLog_Warn("Response Destination mismatch ('%s' vs. '%s')",
                   attr->value, profile->assertionConsumerURL);
        reason = "response destination mismatch";
        goto samlerr;
    }
    attr = (WXMLAttribute *) WXML_Find(root, "@InResponseTo", FALSE);
    respInResponseTo = ((attr != NULL) ? attr->value : NULL);

    /* Prepare for session attribute collection */
    if (!WXDict_Init(&attributes, 16, FALSE)) goto memfail;

    /* Validations of response assertions according to SAML spec 4.1.4.2/3 */
    nameId = NULL;
    for (node = root->children; node != NULL; node = node->next) {
        /* Just interested in assertions */
        if ((node->name == NULL) ||
                   (strcmp(node->name, "Assertion") != 0)) continue;

        /* Each assertion is validated separately */
        conf = NULL;

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
            reason = "assertion missing issuer";
            goto samlerr;
        }
        attr = WXML_Find(chld, "@Format", FALSE);
        if (attr != NULL) {
            if ((attr->value == NULL) ||
                (strcmp(attr->value,
                    "urn:oasis:names:tc:SAML:2.0:nameid-format:entity") != 0)) {
                WXLog_Error("Incorrect Issuer Format '%s'",
                            ((attr->value == NULL) ? "" : attr->value));
                reason = "incorrect issuer format";
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

        /* Bearer confirmation requires time validation */
        if ((conf != NULL) &&
                (!validateTimeWindow(conf, "SubjectConfirmationData",
                                     profile->clockSkew, TRUE))) {
            conf = NULL;
        }

        /* As do Conditions if present */
        if ((conf != NULL) &&
                ((chld = WXML_Find(node, "/Conditions", FALSE)) != NULL) &&
                (!validateTimeWindow(chld, "Conditions",
                                     profile->clockSkew, FALSE))) {
            conf = NULL;
        }

        /* Validate Audience response, if provided */
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

        /* Must have a subject NameID for logging */
        val = NULL;
        if (conf != NULL) {
            val = WXML_Find(conf->parent->parent, "/NameID", FALSE);
            if ((val == NULL) || (val->content == NULL)) {
                WXLog_Warn("Assertion Subject missing NameID, skipping");
                conf = NULL;
            }
        }

        /* Finally, verify InResponseTo to avoid replay attacks */
        if ((conf != NULL) &&
                (((attr = WXML_Find(conf, "/@InResponseTo", FALSE)) == NULL) ||
                     (attr->value == NULL))) {
            WXLog_Warn("Assertion Subject missing InResponseTo, skipping");
            conf = NULL;
        } else if ((conf != NULL) && (respInResponseTo != NULL) &&
                       (strcmp(respInResponseTo, attr->value) != 0)) {
            WXLog_Warn("Assertion/Response InResponseTo mismatch, skipping");
            conf = NULL;
        } else if (conf != NULL) {
            (void) WXThread_MutexLock(&(profile->reqLock));
            reqSession = WXHash_GetEntry(&(profile->reqSessions), attr->value,
                                         WXHash_StrHashFn, WXHash_StrEqualsFn);
            if (reqSession != NULL) {
                (void) WXHash_RemoveEntry(&(profile->reqSessions), attr->value,
                                          NULL, NULL, WXHash_StrHashFn,
                                          WXHash_StrEqualsFn);
            }
            (void) WXThread_MutexUnlock(&(profile->reqLock));

            if (reqSession == NULL) {
                WXLog_Warn("Unsolicited or replay Assertion, skipping");
                conf = NULL;
            } else {
                /* Steal the destination for use in the redirect */
                if (destURL != NULL) WXFree(destURL);
                destURL = reqSession->destURL;  reqSession->destURL = NULL;
                WXFree(reqSession->reqSessionId);
                WXFree(reqSession);
            }
        }

        /* If we still have a subject verification reference, it's valid */
        if (conf == NULL) continue;
        nameId = val->content;
        WXLog_Debug("Validated principal assertion for '%s'", nameId);

        /* TODO - grab the optional elements as well */
        /* AuthnStatement/@SessionIndex */
        /* AuthnStatement/@SessionNotOnOrAfter */

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
        WXLog_Error("Invalid SAML response, no asserted user identity");
        NGXMGR_SessionLog("[%s] SAML login rejected: no validated assertion",
                          sourceIpAddr);
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
        if ((GlobalData.dbConnPool == NULL) || (profile->isExtAuthOnly)) {
            NGXMGR_SessionLog("[%s] SAML login accepted for '%s'",
                              sourceIpAddr, nameId);
            NGXMGR_AllocateNewSession(-1, sourceIpAddr, -1, &attributes,
                                      (destURL != NULL) ? destURL :
                                                          prf->defaultIndex,
                                      conn, StdSessionEstablishHandler);
        } else if (strlen(sourceIpAddr) >= sizeof(info->sourceIpAddr)) {
            WXLog_Error("Invalid source address for SAML login completion");
            NGXMGR_IssueErrorResponse(conn, 400, "Invalid Request",
                                      "Invalid source address in request");
        } else {
            /* Could fold together but keep alignment with old event model */
            info = (SAMLLoginInfo *) WXCalloc(sizeof(SAMLLoginInfo));
            if (info == NULL) goto memfail;
            info->prf = prf;
            info->conn = conn;
            (void) strcpy(info->sourceIpAddr, sourceIpAddr);
            info->destURL = destURL;
            info->attributes = attributes;

            /* Nullify to prevent cleanup mucking up handoff */
            destURL = NULL;
            (void) memset(&attributes, 0, sizeof(WXDictionary));

            samlLoginFinish(info);
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
    NGXMGR_SessionLog("[%s] SAML login rejected: %s", sourceIpAddr, reason);
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
    if (signedRefs != NULL) WXML_FreeLinkedElements(signedRefs);
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
    if ((action != NULL) && (strcmp(action, "login") == 0) &&
            (strncmp(request, "PST", 3) == 0)) {
        SAMLLogin(prof, conn, sourceIpAddr, data, dataLen);
    } else {
        /* Log without query paramaters (tokens) */
        WXLog_Error("Unrecognized action/request: %s - %.*s",
                    ((action != NULL) ? action : "(none)"),
                    (int) strcspn(request, "?"), request);
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
