/**
 * What it's all about, managing session instances!
 * 
 * Copyright (C) 2018-2020 J.M. Heisz.  All Rights Reserved.
 * See the LICENSE file accompanying the distribution your rights to use
 * this software.
 */
#include "stdconfig.h"
#include <openssl/rand.h>
#include "manager.h"
#include "hash.h"
#include "thread.h"
#include "log.h"
#include "mem.h"

/* Tracking structure for active session instances */
typedef struct NGXMGRSession {
    char *sessionId, *sourceIpAddr;
    time_t established, lastAccess, expiry;
    WXBuffer attributes;
} NGXMGRSession;

/* The master active sessions table and the mutex accessor for it */
static WXHashTable sessions;
static WXThread_Mutex sessionsLock = WXTHREAD_MUTEX_STATIC_INIT;
static int sessionsInitialized = FALSE;

/* Initialization method for the sessions, might be re-entrant for errors */
void NGXMGR_InitializeSessions() {
    int idx;

    if (sessionsInitialized) return;

    /* At the lowest level, it's just a hashtable! */
    if (!WXHash_InitTable(&sessions, 1024)) {
        WXLog_Error("Failed to initialize sessions management hashtable");
        exit(1);
    }

    /* Quick completion if memory-only session management */
    if (GlobalData.dbConnPool == NULL) {
        sessionsInitialized = TRUE;
        return;
    }

    /* TODO - preload from database, duh */
}

/* Looks like base-64 but it's not */
static uint8_t encbytes[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                              'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                              'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                              'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                              'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                              'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                              'w', 'x', 'y', 'z', '0', '1', '2', '3',
                              '4', '5', '6', '7', '8', '9', '_', '.' };

/* Generate a session identifier string based on configuration */
char *NGXMGR_GenerateSessionId(int idlen) {
    int idx, dlen =  3 * (idlen / 4) + 3;
    uint8_t *ptr, *str, *retval;
    uint32_t datum;

    /* Initialize as best as possible the OpenSSL random buffer */
    for (idx = 0; idx < 8; idx++) {
        if (RAND_status() == 1) break;
        if (RAND_poll() == 0) break;
    }

    /* In place 64-bit random encoding, sort of */
    retval = (uint8_t *) WXMalloc(idlen + 5);
    if (retval == NULL) return NULL;
    if (RAND_bytes(retval, dlen) != 1) {
        /* Psuedo-random it is */
        for (idx = 0; idx < dlen; idx++) {
            retval[idx] = random() & 0xFF;
        }
    }
    ptr = retval + dlen - 1;
    str = retval + 4 * (dlen / 3) - 1;
    while (ptr >= retval) {
        datum = *(ptr--) << 0x10;
        datum += *(ptr--) << 0x08;
        datum += *(ptr--);
        *(str--) = encbytes[(datum >> 18) & 0x3F];
        *(str--) = encbytes[(datum >> 12) & 0x3F];
        *(str--) = encbytes[(datum >> 6) & 0x3F];
        *(str--) = encbytes[datum & 0x3F];
    }
    /* Thanks Microsoft, make sure first digit is a letter */
    retval[0] = encbytes[retval[0] % 52];
    retval[idlen] = '\0';

    return retval;
}

/* Validate the indicated session, taking lifespan and source IP into account */
int NGXMGR_ValidateSession(char *sessionId, char *sourceIpAddr,
                           WXBuffer *attrs) {
    time_t currentTm = time((time_t *) NULL);
    NGXMGRSession *session = NULL;
    int sessionIsValid = FALSE;

    /* Pretty straightforward, lookup/validate under global MT lock */
    (void) WXThread_MutexLock(&sessionsLock);
    session == WXHash_GetEntry(&sessions, sessionId, WXHash_StrHashFn,
                               WXHash_StrEqualsFn);
    if (session != NULL) {
        if ((currentTm > session->expiry) ||
                ((GlobalData.sessionIdleTime > 0) &&
                     ((currentTm - session->lastAccess) >
                                         GlobalData.sessionIdleTime))) {
            /* Session has expired or is inactive */
            sessionIsValid = FALSE;
        } else if (GlobalData.sessionIPLocked) {
            /* Session is valid only if IP address has not changed */
            sessionIsValid = (strcmp(session->sourceIpAddr, sourceIpAddr) == 0);
        } else {
            /* Session is valid, even if on the move */
            sessionIsValid = TRUE;
        }
    }

    if (sessionIsValid) {
        /* Copy attributes response */
        if (WXBuffer_Duplicate(attrs, &(session->attributes)) == NULL) {
            /* Things are going very bad, just avoid a crash */
            return FALSE;
        }

        /* Update last access time (presuming validate is bound to that) */
        session->lastAccess = currentTm;
    } else if (session != NULL) {
        /* Remove the entry under lock if defined but invalid */
        (void) WXHash_RemoveEntry(&sessions, sessionId, NULL, NULL,
                                  WXHash_StrHashFn, WXHash_StrEqualsFn);
    }
    (void) WXThread_MutexUnlock(&sessionsLock);

    /* Handle cleanup (including database flush) outside of lock */
    if ((!sessionIsValid) && (session != NULL)) {
        /* TODO - database flush! */
        WXFree(session->sessionId);
        WXFree(session->sourceIpAddr);
        WXFree(session);
    }

    return sessionIsValid;
}

/* Scanning encoder for the session attributes */
static int encodeAttribute(WXDictionary *dict, const char *key,
                           const char *val, void *userData) {
    WXBuffer *buffer = (WXBuffer *) userData;

    return (WXBuffer_Pack(buffer, "sa*csa*c",
                          (uint16_t) strlen(key), key, (uint8_t) 0,
                          (uint16_t) strlen(val), val, (uint8_t) 0) == NULL);
}

/* Allocate a session instance, based on external authentication actions */
void NGXMGR_AllocateNewSession(char *sourceIpAddr, time_t expiry,
                               WXDictionary *attributes,
                               NGXModuleConnection *conn,
                               NGXMGR_CompleteSessionHandler handler) {
    NGXMGRSession *session;

    /* Build the session tracking instance */
    session = (NGXMGRSession *) WXCalloc(sizeof(NGXMGRSession));
    if (session == NULL) goto memfail;
    session->sessionId = NGXMGR_GenerateSessionId(GlobalData.sessionIdLen);
    if (session->sessionId == NULL) goto memfail;
    session->sourceIpAddr = (char *) WXMalloc(strlen(sourceIpAddr) + 1);
    (void) strcpy(session->sourceIpAddr, sourceIpAddr);
    session->established = session->lastAccess = time((time_t *) NULL);
    if (GlobalData.sessionLifespan >= 0) {
        session->expiry = session->established + GlobalData.sessionLifespan;
    } else {
        /* 100 years aughtta do it */
        session->expiry = session->established + 100L * 365 * 86400;
    }
    if ((expiry > 0) && (expiry < session->expiry)) session->expiry = expiry;

    /* Assemble the attributes buffer, starting with the session id */
    if (WXBuffer_Init(&(session->attributes), 1024) == NULL) goto memfail;
    if (encodeAttribute(NULL, "sid", session->sessionId,
                        &(session->attributes))) goto memfail;
    if (WXDict_Scan(attributes, encodeAttribute, 
                    &(session->attributes))) goto memfail;

    /* Record it appropriately */
    if (GlobalData.dbConnPool != NULL) {
        /* TODO - database storage with callback */
    } else {
        /* No database, memory sessions only */
        (void) WXThread_MutexLock(&sessionsLock);
        if (!WXHash_InsertEntry(&sessions, session->sessionId, session,
                                NULL, NULL, WXHash_StrHashFn,
                                WXHash_StrEqualsFn)) {
            (void) WXThread_MutexUnlock(&sessionsLock);
            goto memfail;
        }

        /* Note: callback handler must not block, under session lock! */
        (*handler)(conn, session->sessionId, &(session->attributes));
        (void) WXThread_MutexUnlock(&sessionsLock);
    }
    return;

memfail:
    WXLog_Error("Memory allocation failure on creating session record");
    if (session->attributes.buffer != NULL)
                        WXBuffer_Destroy(&(session->attributes));
    if (session->sourceIpAddr != NULL) WXFree(session->sourceIpAddr);
    if (session->sessionId != NULL) WXFree(session->sessionId);
    if (session != NULL) WXFree(session);
    (*handler)(conn, NULL, NULL);
}
