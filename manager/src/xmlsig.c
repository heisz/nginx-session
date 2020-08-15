/**
 * Core elements for XML signature/reference (V1.1) verification.
 * 
 * Copyright (C) 2018-2020 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#include "stdconfig.h"
#include <openssl/x509.h>
#include <openssl/err.h>
#include "manager.h"
#include "xml.h"
#include "hash.h"
#include "log.h"

/* This could be in toolkit someday, but it's pretty platform specific */

/* Wrapper for logging OpenSSL errors */
static int openSSLErrCB(const char *str, size_t len, void *u) {
    uint32_t lvlLine = (uint32_t) (intptr_t) u;
fprintf(stderr, "CB\n");
    _WXLog_Print(__FILE__, lvlLine & 0x00FFFFFF, ((lvlLine >> 24) & 0xFF),
                 "%*s", (int) len, str);
}
#define WXLog_OpenSSLErr(level) \
    ERR_print_errors_cb(openSSLErrCB, \
                        (void *) (intptr_t) ((level << 24) | __LINE__));

/* Cleanup method for the linked element return */
void WXML_FreeLinkedElements(WXMLLinkedElement *list) {
    WXMLLinkedElement *next;

    while (list != NULL) {
        next = list->nextElmnt;
        WXFree(list);
        list = next;
    }
}

/* Utilities to pull elements in document order, skipping text segments */
static WXMLElement *getFirstElement(WXMLElement *parent) {
    WXMLElement *child = parent->children;
    while (child != NULL) {
        if (child->name != NULL) return child;
        child = child->next;
    }
    return NULL;
}
static WXMLElement *getNextElement(WXMLElement *start) {
    if ((start == NULL) || ((start = start->next) == NULL)) return NULL;
    while (start != NULL) {
        if (start->name != NULL) return start;
        start = start->next;
    }
    return NULL;
}

/* Broken out method to process single reference with cleanup */
static void validateReference(WXMLLinkedElement **signedRefs,
                              WXMLElement *refElmnt, WXHashTable *idMap) {
    uint8_t encData[2048], *digest= NULL;
    BIO *base64Dec, *base64Buff = NULL;
    WXMLLinkedElement *lelmnt, *entry;
    WXMLElement *target, *digValue;
    EVP_MD_CTX *mdctx = NULL;
    WXMLAttribute *attr;
    WXBuffer encBuffer;
    unsigned int dlen;
    int rc, diglen;

    /* Per spec, URI is optional if external, that's not the case here */
    /* (or XMLSig 2.0 which this code does not support) */
    attr = (WXMLAttribute *) WXML_Find(refElmnt, "@URI", FALSE);
    if (attr == NULL) {
        WXLog_Warn("Reference element missing URI attribute, ignoring");
        return;
    }

    /* And URI target must be an internal object reference */
    if ((*(attr->value) != '#') ||
            ((target = WXHash_GetEntry(idMap, attr->value + 1,
                                       WXHash_StrHashFn,
                                       WXHash_StrEqualsFn)) == NULL)) {
        WXLog_Warn("Invalid/unresolved URI for Reference, ignoring");
        return;
    }

    /*
     * For the sake of getting this all working, the implementation
     * currently ignores the Transforms definition of the Reference.
     * Or, more succinctly, if the IdP does not state the following:
     * <Transforms>
     *   <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#
     *                                              enveloped-signature"/>
     *   <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
     * </Transforms>
     *
     * it's a more recent example using transforms this code does not know
     * about, so it's just going to fail anyways...
     */

    /* Also see note below about non-XSD compliant content in Signature */

    /* Exclusive c14n the target, minus the enveloped Signature content */
    WXBuffer_InitLocal(&encBuffer, encData, sizeof(encData));
    if (WXML_Canonicalize(&encBuffer, target, refElmnt->parent->parent,
                          FALSE) == NULL) goto memfail;

    /* Pull the digest value before churning the digest structures */
    digValue = WXML_Find(refElmnt, "DigestValue", FALSE);
    if (digValue == NULL) {
        WXLog_Warn("Missing DigestValue in Reference content");
        WXBuffer_Destroy(&encBuffer);
        return;
    }
    diglen = strlen(digValue->content);
    digest = WXMalloc(diglen + 2);
    if (digest == NULL) goto memfail;
    base64Buff = BIO_new_mem_buf(digValue->content, diglen);
    base64Dec = BIO_new(BIO_f_base64());
    if ((base64Buff == NULL) || (base64Dec == NULL)) goto memfail;
    base64Buff = BIO_push(base64Dec, base64Buff);
    BIO_set_flags(base64Buff, BIO_FLAGS_BASE64_NO_NL);
    diglen = BIO_read(base64Buff, digest, diglen);
    BIO_free_all(base64Buff); base64Buff = NULL;

    /* Determine/initialize the digest method */
    attr = WXML_Find(refElmnt, "DigestMethod/@Algorithm", FALSE);
    if ((attr == NULL) || (attr->value == NULL)) {
        WXLog_Warn("No <DigestMethod> @Algorithm found/specified");
        WXBuffer_Destroy(&encBuffer);
        return;
    }

    if ((mdctx = EVP_MD_CTX_new()) == NULL) goto memfail;
    if (strcmp(attr->value,
               "http://www.w3.org/2001/04/xmldsig-more#sha224") == 0) {
        if ((rc = EVP_DigestInit(mdctx, EVP_sha224())) != 1) {
            WXLog_Error("Error in EVP_DigestVerifyInit(): %d/%d",
                        rc, (int) ERR_get_error());
            WXLog_OpenSSLErr(WXLOG_ERROR);
            goto errclean;
        }
    } else if (strcmp(attr->value,
                      "http://www.w3.org/2001/04/xmlenc#sha256") == 0) {
        if ((rc = EVP_DigestInit(mdctx, EVP_sha256())) != 1) {
            WXLog_Error("Error in EVP_DigestVerifyInit(): %d/%d",
                        rc, (int) ERR_get_error());
            WXLog_OpenSSLErr(WXLOG_ERROR);
            goto errclean;
        }
    } else if (strcmp(attr->value,
                      "http://www.w3.org/2001/04/xmldsig-more#sha384") == 0) {
        if ((rc = EVP_DigestInit(mdctx, EVP_sha384())) != 1) {
            WXLog_Error("Error in EVP_DigestVerifyInit(): %d/%d",
                        rc, (int) ERR_get_error());
            WXLog_OpenSSLErr(WXLOG_ERROR);
            goto errclean;
        }
    } else if (strcmp(attr->value,
                      "http://www.w3.org/2001/04/xmlenc#sha512") == 0) {
        if ((rc = EVP_DigestInit(mdctx, EVP_sha512())) != 1) {
            WXLog_Error("Error in EVP_DigestVerifyInit(): %d/%d",
                        rc, (int) ERR_get_error());
            WXLog_OpenSSLErr(WXLOG_ERROR);
            goto errclean;
        }
    } else {
        WXLog_Warn("Unrecognized <DigestMethod> @Algorithm specified");
        goto errclean;
    }

    /* Digest the canonicalized data, using the internal buff for return */
    if ((rc = EVP_DigestUpdate(mdctx, encBuffer.buffer,
                               encBuffer.length - 1)) != 1) {
        WXLog_Error("Failed to update Reference digest: %d/%d",
                    rc, (int) ERR_get_error());
        WXLog_OpenSSLErr(WXLOG_ERROR);
        goto errclean;
    }
    if ((rc = EVP_DigestFinal(mdctx, encData, &dlen)) != 1) {
        WXLog_Error("Failed to finalize Reference digest: %d/%d",
                    rc, (int) ERR_get_error());
        WXLog_OpenSSLErr(WXLOG_ERROR);
        goto errclean;
    }

    /* Moment of truth, accept or decline referenced element */
    if ((dlen != diglen) || (memcmp(encData, digest, diglen) != 0)) {
        WXLog_Warn("Mismatched Reference digest value, ignoring");
    } else {
        lelmnt = (WXMLLinkedElement *) WXMalloc(sizeof(WXMLLinkedElement));
        if (lelmnt == NULL) goto memfail;
        lelmnt->elmnt = target;
        lelmnt->nextElmnt = NULL;

        if (*signedRefs == NULL) {
            *signedRefs= lelmnt;
        } else {
            entry = *signedRefs;
            while (entry->nextElmnt != NULL) entry = entry->nextElmnt;
            entry->nextElmnt = lelmnt;
        }
    }

    /* Clean up now that we are finished */
    EVP_MD_CTX_destroy(mdctx);
    WXBuffer_Destroy(&encBuffer);
    WXFree(digest);
    return;

    /* Not liking gotos except for repeating error handling */
memfail:
    WXLog_Error("Memory allocation error during reference validation");
errclean:
    WXBuffer_Destroy(&encBuffer);
    if (digest != NULL) WXFree(digest);
    if (base64Buff != NULL) BIO_free_all(base64Buff);
    if (mdctx != NULL) EVP_MD_CTX_destroy(mdctx);
}

/* Encapulated wrapper to loop on the above */
static void validateReferences(WXMLLinkedElement **signedRefs,
                               WXMLElement *sigElmnt, WXHashTable *idMap) {
    WXMLElement *signedInfo, *refScan;

    /* This was validated in signature, safe to assume */
    signedInfo = getFirstElement(sigElmnt);

    /* Hunt down the child references */
    refScan = getFirstElement(signedInfo);
    while (refScan != NULL) {
        if (strcmp(refScan->name, "Reference") != 0) {
            refScan = refScan->next;
            continue;
        }

        /* All of the complexity is bundled to simplify cleanup */
        validateReference(signedRefs, refScan, idMap);

        refScan = refScan->next;
    }
}

/* Encapsulated method for verifying the signature of a <Signature> element */
static int validateSignature(WXMLElement *sigElmnt, EVP_PKEY *key) {
    WXMLElement *signedInfo, *sigValue;
    uint8_t encData[2048], *signature = NULL;
    BIO *base64Dec, *base64Buff = NULL;
    EVP_MD_CTX *mdctx = NULL;
    WXMLAttribute *attr;
    WXBuffer encBuffer;
    int rc, siglen;

    /*
     * Security note: the top-level required contents of the <Signature>
     * element are XSD validated.  However, content inside the <SignedInfo>
     * is retrieved in a relaxed manner - if the IdP chooses to inject invalid
     * content and sign it appropriately, there are bigger security issues.
     * This implementation also forces external key provision, so trailing key
     * information in the signature is ignored.
     */

    /* Also, right now, this only works for XML Signature 1.1 */
    if ((sigElmnt->namespace != NULL) &&
            (strcmp(sigElmnt->namespace->href,
                    "http://www.w3.org/2000/09/xmldsig#") != 0)) {
        WXLog_Warn("Found <Signature> but unsupported version");
        return FALSE;
    }

    /* Get and canonicalize the <SignedInfo> element (must be first per XSD) */
    WXBuffer_InitLocal(&encBuffer, encData, sizeof(encData));
    signedInfo = getFirstElement(sigElmnt);
    if ((signedInfo == NULL) || (strcmp(signedInfo->name, "SignedInfo") != 0)) {
        WXLog_Warn("Found <Signature> but missing <SignedInfo> in content");
        return FALSE;
    }
    attr = (WXMLAttribute *) WXML_Find(signedInfo,
                                       "CanonicalizationMethod/@Algorithm",
                                       FALSE);
    if ((attr == NULL) || (attr->value == NULL) ||
            (strncmp(attr->value,
                     "http://www.w3.org/2001/10/xml-exc-c14n#", 39) != 0)) {
        WXLog_Warn("Missing or unrecognized c14n algorithm: %s",
                   (((attr == NULL) || (attr->value == NULL)) ? "null" :
                                                                attr->value));
        /* Not much we can do, signing will just go poorly */
    }
    if (WXML_Canonicalize(&encBuffer, signedInfo,
                          NULL, FALSE) == NULL) goto memfail;

    /* Likewise, find and decode (base 64) the signature value */
    sigValue = getNextElement(signedInfo);
    if ((sigValue == NULL) || (strcmp(sigValue->name, "SignatureValue") != 0)) {
        WXLog_Warn("Found <Signature> but missing <SignatureValue> in content");
        WXBuffer_Destroy(&encBuffer);
        return FALSE;
    }
    siglen = strlen(sigValue->content);
    signature = WXMalloc(siglen + 2);
    if (signature == NULL) goto memfail;
    base64Buff = BIO_new_mem_buf(sigValue->content, siglen);
    base64Dec = BIO_new(BIO_f_base64());
    if ((base64Buff == NULL) || (base64Dec == NULL)) goto memfail;
    base64Buff = BIO_push(base64Dec, base64Buff);
    BIO_set_flags(base64Buff, BIO_FLAGS_BASE64_NO_NL);
    siglen = BIO_read(base64Buff, signature, siglen);
    BIO_free_all(base64Buff); base64Buff = NULL;

    /* Determine the appropriate model for signing */
    attr = (WXMLAttribute *) WXML_Find(signedInfo, "SignatureMethod/@Algorithm",
                                       FALSE);
    if ((attr == NULL) || (attr->value == NULL)) {
        WXLog_Warn("No <SignatureMethod> @Algorithm found/specified");
        WXBuffer_Destroy(&encBuffer);
        WXFree(signature);
        return FALSE;
    }

    /* Big switch for the supported signing options through OpenSSL */
    /* Note that the key contains the asymmetric encoding details */
    if ((mdctx = EVP_MD_CTX_new()) == NULL) goto memfail;
    if (strcmp(attr->value,
               "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") == 0) {
        if ((rc = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(),
                                       NULL, key)) != 1) {
            WXLog_Error("Error in EVP_DigestVerifyInit(): %d/%d",
                        rc, (int) ERR_get_error());
            WXLog_OpenSSLErr(WXLOG_ERROR);
            goto errclean;
        }
    } else if (strcmp(attr->value,
                      "http://www.w3.org/2001/04/xmldsig#rsa-sha1") == 0) {
        if ((rc = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha1(),
                                       NULL, key)) != 1) {
            WXLog_Error("Error in EVP_DigestVerifyInit(): %d/%d",
                        rc, (int) ERR_get_error());
            WXLog_OpenSSLErr(WXLOG_ERROR);
            goto errclean;
        }
    } else if (strcmp(attr->value,
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224") == 0) {
        if ((rc = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha224(),
                                       NULL, key)) != 1) {
            WXLog_Error("Error in EVP_DigestVerifyInit(): %d/%d",
                        rc, (int) ERR_get_error());
            WXLog_OpenSSLErr(WXLOG_ERROR);
            goto errclean;
        }
    } else if (strcmp(attr->value,
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") == 0) {
        if ((rc = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(),
                                       NULL, key)) != 1) {
            WXLog_Error("Error in EVP_DigestVerifyInit(): %d/%d",
                        rc, (int) ERR_get_error());
            WXLog_OpenSSLErr(WXLOG_ERROR);
            goto errclean;
        }
    } else if (strcmp(attr->value,
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384") == 0) {
        if ((rc = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha384(),
                                       NULL, key)) != 1) {
            WXLog_Error("Error in EVP_DigestVerifyInit(): %d/%d",
                        rc, (int) ERR_get_error());
            WXLog_OpenSSLErr(WXLOG_ERROR);
            goto errclean;
        }
    } else if (strcmp(attr->value,
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512") == 0) {
        if ((rc = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha512(),
                                       NULL, key)) != 1) {
            WXLog_Error("Error in EVP_DigestVerifyInit(): %d/%d",
                        rc, (int) ERR_get_error());
            WXLog_OpenSSLErr(WXLOG_ERROR);
            goto errclean;
        }
    } else {
        WXLog_Warn("Unrecognized <SignatureMethod> @Algorithm specified");
        goto errclean;
    }

    /* Digest the canonical content (watch for trailing null character!) */
    if ((rc = EVP_DigestVerify(mdctx, signature, siglen, encBuffer.buffer,
                               encBuffer.length - 1)) != 1) {
        WXLog_Error("Signature verification failed: %d/%d",
                    rc, (int) ERR_get_error());
        WXLog_OpenSSLErr(WXLOG_ERROR);
        goto errclean;
    }

    /* If we got to here, signature is valid, just clean up */
    EVP_MD_CTX_destroy(mdctx);
    WXBuffer_Destroy(&encBuffer);
    WXFree(signature);
    return TRUE;

    /* Again, not liking gotos except for repeating error handling */
memfail:
    WXLog_Error("Memory allocation error during signature validation");
errclean:
    WXBuffer_Destroy(&encBuffer);
    if (signature != NULL) WXFree(signature);
    if (base64Buff != NULL) BIO_free_all(base64Buff);
    if (mdctx != NULL) EVP_MD_CTX_destroy(mdctx);
    return FALSE;
}

/* Scanner for recursively searching for signatures, process from there */
static void signatureScan(WXMLElement *doc, WXMLElement *elmnt,
                          WXMLLinkedElement **signedRefs, WXHashTable *idMap,
                          EVP_PKEY *key) {
    WXMLElement *child = elmnt->children;

    /* Just scan the children, recursing or redirecting based on Signature... */
    while (child != NULL) {
        if (child->name != NULL) {
            if (strcmp(child->name, "Signature") == 0) {
                if (validateSignature(child, key)) {
                    /* Woohoo!  Signature is valid, check for references */
                    validateReferences(signedRefs, child, idMap);
                }
            } else {
                signatureScan(doc, child, signedRefs, idMap, key);
            }
        }
        child = child->next;
    }
}

/* Scanner for recursively building ID map of document, *without* duplicates */
static void idScan(WXMLElement *elmnt, WXHashTable *idMap) {
    WXMLElement *child = elmnt->children, *oldEntry;
    WXMLAttribute *attr = elmnt->attributes;
    char *id;

    /* Find ID and insert, pushing NULL for duplicated instances */
    while (attr != NULL) {
        if (strcasecmp(attr->name, "id") == 0) {
            if (!WXHash_InsertEntry(idMap, attr->value, elmnt,
                                    NULL, (void **) &oldEntry,
                                    WXHash_StrHashFn, WXHash_StrEqualsFn)) {
                /* Duplicate - if non-NULL return, make it that way! */
                if (oldEntry != NULL) {
                    (void) WXHash_PutEntry(idMap, attr->value, NULL, NULL, NULL,
                                          WXHash_StrHashFn, WXHash_StrEqualsFn);
                }
            }
        }
        attr = attr->next;
    }

    /* Repeat for the children */
    while (child != NULL) {
        if (child->name != NULL) idScan(child, idMap);
        child = child->next;
    }
}

/**
 * Verify the signed references of the provided XML document.
 *
 * @param doc The parsed document instance to be verified.
 * @param key The public key to use in signature verification.
 * @return Linked list of XML elements in the document that are signed/ref'd and
 *         validated.  Note that a memory failure ends processing and could
 *         leave an incomplete list, so NULL means no valid elements or memory
 *         failure on initial processing.
 */
WXMLLinkedElement *WXML_ValidateSignedReferences(WXMLElement *doc,
                                                 EVP_PKEY *key) {
    WXMLLinkedElement *retval = NULL;
    WXHashTable idMap;

    /* This only supports well-behaved ID references */
    /* Also, avoid largest security hole - foreign ID injection/replay */
    if ((!WXHash_InitTable(&idMap, 16)) ||
            (!WXHash_PutEntry(&idMap, "", doc, NULL, NULL,
                              WXHash_StrHashFn, WXHash_StrEqualsFn))) {
        WXLog_Error("Memory allocation failure initializing id map");
        return NULL;
    }
    idScan(doc, &idMap);

    /* Just hand off to the recursive Signature element scan */
    signatureScan(doc, doc, &retval, &idMap, key);

    /* Tidy up */
    WXHash_Destroy(&idMap);

    return retval;
}
