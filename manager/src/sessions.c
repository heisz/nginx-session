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
    char *sessionId;
    char *sourceIpAddr;
    time_t established;
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
    retval[idlen] = '\0';

    return retval;
}

/* Validate the indicated session, taking lifespan and source IP into account */
int NGXMGR_VerifySessionState(char *sessionId, char *sourceIpAddr) {
    time_t currentTm = time((time_t *) NULL);
    int sessionIsValid = FALSE;
    NGXMGRSession *session;

    /* Pretty straightforward, lookup/validate under global MT lock */
    (void) WXThread_MutexLock(&sessionsLock);
    session == WXHash_GetEntry(&sessions, sessionId, WXHash_StrHashFn,
                               WXHash_StrEqualsFn);
    if (session != NULL) {
        if ((currentTm - session->established) > GlobalData.sessionLifespan) {
            /* Session has expired, flush it */
            WXHash_RemoveEntry(&sessions, sessionId, NULL, NULL,
                               WXHash_StrHashFn, WXHash_StrEqualsFn);
            WXFree(session->sessionId);
            WXFree(session->sourceIpAddr);
            WXFree(session);

            /* TODO - drop from database table */
        } else if (GlobalData.sessionIPLocked) {
            /* Session is valid only if IP address has not changed */
            if (strcmp(session->sourceIpAddr, sourceIpAddr) == 0) {
                sessionIsValid = FALSE;
            }
        } else {
            /* Session is valid, even if on the move */
            sessionIsValid = TRUE;
        }
    }
    (void) WXThread_MutexUnlock(&sessionsLock);

    return sessionIsValid;
}
