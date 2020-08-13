/**
 * Core elements for XML signature/reference verification.
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

/* And simplified method to append to a list of linked elements */
static void WXML_AppendElement(WXMLLinkedElement *list, WXMLElement *elmnt) {
    while (list->nextElmnt != NULL) list = list->nextElmnt;
    list->nextElmnt = (WXMLLinkedElement *) WXMalloc(sizeof(WXMLLinkedElement));
    if (list->nextElmnt == NULL) {
        WXLog_Error("Memory failure during signature processing");
        return;
    }
    list->nextElmnt->elmnt = elmnt;
    list->nextElmnt->nextElmnt = NULL;
}

/* Core method for verifying the signature of a <Signature> element */
static int validateSignature(WXMLElement *sigElmnt, EVP_PKEY *key) {
    WXMLElement *signedInfo, *sigValue;
    uint8_t encData[2048], *signature = NULL;
    BIO *base64Dec, *base64Buff = NULL;
    EVP_MD_CTX *mdctx = NULL;
    WXMLAttribute *attr;
    WXBuffer encBuffer;
    int rc, siglen;

    /* Find and canonicalize the <SignedInfo> element */
    WXBuffer_InitLocal(&encBuffer, encData, sizeof(encData));
    signedInfo = (WXMLElement *) WXML_Find(sigElmnt, "SignedInfo", FALSE);
    if (signedInfo == NULL) {
        WXLog_Warn("Found <Signature> but no <SignedInfo> in content");
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
    sigValue = (WXMLElement *) WXML_Find(sigElmnt, "SignatureValue", FALSE);
    if (sigValue == NULL) {
        WXLog_Warn("Found <Signature> but no <SignatureValue> in content");
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
        WXLog_Warn("No <SignatureMethod> Algorithm found/specified!");
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
    } else {
        WXLog_Warn("Unrecognized SignatureMethod Algorithm specified!");
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
static void signatureScan(WXMLElement *elmnt, WXMLLinkedElement **signedRefs,
                          EVP_PKEY *key) {
    WXMLElement *child = elmnt->children;

    /* Just scan the children, recursing or redirecting based on Signature... */
    while (child != NULL) {
        if (child->name != NULL) {
            if (strcmp(child->name, "Signature") == 0) {
                if (validateSignature(child, key)) {
fprintf(stderr, "SIGNATURE VALID!!!!!!\n");
                }
            } else {
                signatureScan(child, signedRefs, key);
            }
        }
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

    /* Just hand off to the recursive Signature element scan */
    signatureScan(doc, &retval, key);
    return retval;
}
