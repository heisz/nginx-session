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
    int userId;
    char *sessionId, *sourceIpAddr;
    time_t established, lastAccess, expiry;
    WXBuffer attributes;
} NGXMGRSession;

/* Common cleanup method for releasing session record, must be calloc */
static void _destroySession(NGXMGRSession *session) {
    if (session->attributes.buffer != NULL)
                        WXBuffer_Destroy(&(session->attributes));
    if (session->sourceIpAddr != NULL) WXFree(session->sourceIpAddr);
    if (session->sessionId != NULL) WXFree(session->sessionId);
    if (session != NULL) WXFree(session);
}

/* The master active sessions table and the mutex accessor for it */
static WXHashTable sessions;
static WXThread_Mutex sessionsLock = WXTHREAD_MUTEX_STATIC_INIT;
static int sessionsInitialized = FALSE;

/* Initialization method for the sessions, might be re-entrant for errors */
void NGXMGR_InitializeSessions() {
    NGXMGRSession *session;
    WXDBConnection *dbconn;
    WXDBResultSet *rs;
    int idx, cnt = 0;
    const char *val;

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

    /* On restart, prune the session database and reload (empty on failure) */
    dbconn = WXDBConnectionPool_Obtain(GlobalData.dbConnPool);
    if (dbconn == NULL) {
        WXLog_Error("Failed to obtain connection to reinit session list");
        sessionsInitialized = TRUE;
        return;
    }

    if (WXDBConnection_Execute(dbconn,
                               "DELETE FROM ngxsessionmgr.sessions "
                               "WHERE expires < NOW()") < 0) {
        WXLog_Error("Unexpected error purging historical sessions: %s",
                    WXDB_GetLastErrorMessage(dbconn));
    } else {
        WXLog_Info("Purged %d expired session instances",
                   (int) WXDBConnection_RowsModified(dbconn));
    }

    rs = WXDBConnection_ExecuteQuery(dbconn,
                        "SELECT user_id, session_id, source_ipaddr, "
                               "FLOOR(EXTRACT(epoch from established)), "
                               "FLOOR(EXTRACT(epoch from expires)), "
                               "attributes FROM ngxsessionmgr.sessions");
    if (rs == NULL) {
        WXLog_Error("Unexpected error reading existing sessions: %s",
                    WXDB_GetLastErrorMessage(dbconn));
    } else {
        while (WXDBResultSet_NextRow(rs)) {
            cnt++;
            session = (NGXMGRSession *) WXCalloc(sizeof(NGXMGRSession));
            if (session == NULL) break;
            session->userId = atol(WXDBResultSet_ColumnData(rs, 0));

            val = WXDBResultSet_ColumnData(rs, 1);
            session->sessionId = (char *) WXMalloc(strlen(val) + 1);
            if (session->sessionId == NULL) {
                _destroySession(session);
                session = NULL;
                break;
            }
            (void) strcpy(session->sessionId, val);

            val = WXDBResultSet_ColumnData(rs, 2);
            session->sourceIpAddr = (char *) WXMalloc(strlen(val) + 1);
            if (session->sourceIpAddr == NULL) {
                _destroySession(session);
                session = NULL;
                break;
            }
            (void) strcpy(session->sourceIpAddr, val);

            session->established = atoll(WXDBResultSet_ColumnData(rs, 3));
            session->lastAccess = time((time_t *) NULL);
            session->expiry = atoll(WXDBResultSet_ColumnData(rs, 4));

            val = WXDBResultSet_ColumnData(rs, 5);
            if (strncmp(val, "\\x", 2) != 0) {
                WXLog_Error("Invalid binary attribute format result: %s", val);
            } else {
                val += 2;
                if (WXBuffer_Pack(&session->attributes, "H*", val) == NULL) {
                    _destroySession(session);
                    session = NULL;
                    break;
                }
            }

            if (!WXHash_InsertEntry(&sessions, session->sessionId, session,
                                    NULL, NULL, WXHash_StrHashFn,
                                    WXHash_StrEqualsFn)) {
                _destroySession(session);
                session = NULL;
                break;
            }
        }
        if (cnt != 0) {
            if (session == NULL) {
                WXLog_Error("Memory allocation failure loading sessions");
            }
            WXLog_Info("Recovered %d sessions from database", (int) cnt);
        }
        WXDBResultSet_Close(rs);
    }

    /* Always put your toys away */
    WXDBConnectionPool_Return(dbconn);
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
/* TODO - should this validate the non-existence of duplicate session hash */
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

/* Worker thread method to flush underlying database record */
static void *flushSessionRecord(void *arg) {
    NGXMGRSession *session = (NGXMGRSession *) arg;
    WXDBConnection *dbconn;
    char cmdbuff[1024];

    /* Delete the associated session record */
    dbconn = WXDBConnectionPool_Obtain(GlobalData.dbConnPool);
    if (dbconn == NULL) {
        WXLog_Error("Failed to obtain connection to flush session");
    } else {
        (void) sprintf(cmdbuff,
                       "DELETE FROM ngxsessionmgr.sessions "
                       "WHERE session_id = '%s'", session->sessionId);
        if (WXDBConnection_Execute(dbconn, cmdbuff) < 0) {
            WXLog_Error("Unexpected error purging historical sessions: %s",
                        WXDB_GetLastErrorMessage(dbconn));
        }

        WXDBConnectionPool_Return(dbconn);
    }

    /* Regardless of database outcome, clean up memory record */
    _destroySession(session);

    return NULL;
}

/* Validate the indicated session, taking lifespan and source IP into account */
int NGXMGR_ValidateSession(char *sessionId, char *sourceIpAddr,
                           int profileIPLocked, WXBuffer *attrs) {
    time_t currentTm = time((time_t *) NULL);
    NGXMGRSession *session = NULL;
    int sessionIsValid = FALSE;

    /* Pretty straightforward, lookup/validate under global MT lock */
    (void) WXThread_MutexLock(&sessionsLock);
    session = WXHash_GetEntry(&sessions, sessionId, WXHash_StrHashFn,
                              WXHash_StrEqualsFn);
    if (session != NULL) {
        if ((currentTm > session->expiry) ||
                ((GlobalData.sessionIdleTime > 0) &&
                     ((currentTm - session->lastAccess) >
                                         GlobalData.sessionIdleTime))) {
            /* Session has expired or is inactive */
            sessionIsValid = FALSE;
        } else if (GlobalData.sessionIPLocked || profileIPLocked) {
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
            (void) WXThread_MutexUnlock(&sessionsLock);
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
        if (GlobalData.dbConnPool == NULL) {
            /* No database information, just tidy up */
            _destroySession(session);
        } else {
            /* Asynchronously discard the database session record */
            if (WXThreadPool_Enqueue(GlobalData.workerThreadPool,
                                     flushSessionRecord, session) < 0) {
                WXLog_Error("Failed to issue worker for session flush");
                _destroySession(session);
            }
        }
    }

    return sessionIsValid;
}

/* Scanning encoder for the session attributes */
static int encodeAttribute(WXDictionary *dict, const char *key,
                           const char *val, void *userData) {
    WXBuffer *buffer = (WXBuffer *) userData;

    return (WXBuffer_Pack(buffer, "na*cna*c",
                          (uint16_t) strlen(key), key, (uint8_t) 0,
                          (uint16_t) strlen(val), val, (uint8_t) 0) == NULL);
}

/* Allocate a session instance, based on external authentication actions */
/* Note: this method must be in a worker if database access is enabled */
void NGXMGR_AllocateNewSession(int userId, char *sourceIpAddr, time_t expiry,
                               WXDictionary *attributes, char *destURL,
                               NGXModuleConnection *conn,
                               NGXMGR_CompleteSessionHandler handler) {
    NGXMGRSession *session;
    WXDBConnection *dbconn;
    char *ptr, *cmdbuff;
    int idx;

    /* Build the session tracking instance */
    if (destURL == NULL) destURL = "/index.html";
    session = (NGXMGRSession *) WXCalloc(sizeof(NGXMGRSession));
    if (session == NULL) goto memfail;
    session->sessionId = NGXMGR_GenerateSessionId(GlobalData.sessionIdLen);
    if (session->sessionId == NULL) goto memfail;
    session->sourceIpAddr = (char *) WXMalloc(strlen(sourceIpAddr) + 1);
    if (session->sourceIpAddr == NULL) goto memfail;
    (void) strcpy(session->sourceIpAddr, sourceIpAddr);
    session->established = session->lastAccess = time((time_t *) NULL);
    if (GlobalData.sessionLifespan >= 0) {
        session->expiry = session->established + GlobalData.sessionLifespan;
    } else {
        /* 100 years oughtta do it */
        session->expiry = session->established + 100L * 365 * 86400;
    }
    if ((expiry > 0) && (expiry < session->expiry)) session->expiry = expiry;

    /* Assemble the attributes buffer, starting with the session id */
    if (WXBuffer_Init(&(session->attributes), 1024) == NULL) goto memfail;
    if (encodeAttribute(NULL, "sid", session->sessionId,
                        &(session->attributes))) goto memfail;
    if (WXDict_Scan(attributes, encodeAttribute, 
                    &(session->attributes))) goto memfail;

    /* Record it appropriately, if database context is enabled */
    /* Just discard persistence in case of error */
    if (GlobalData.dbConnPool != NULL) {
        dbconn = WXDBConnectionPool_Obtain(GlobalData.dbConnPool);
        if (dbconn == NULL) {
            WXLog_Error("Failed to obtain connection to record session");
        } else {
            cmdbuff = (char *) WXMalloc(session->attributes.length * 2 +
                                        GlobalData.sessionIdLen + 256);
            if (cmdbuff == NULL) {
                WXDBConnectionPool_Return(dbconn);
                goto memfail;
            }

            (void) sprintf(cmdbuff,
                           "INSERT INTO ngxsessionmgr.sessions ("
                                "user_id, session_id, source_ipaddr, "
                                "established, expires, attributes) "
                           "VALUES (%d, '%s', '%s', NOW(), "
                                   "NOW() + interval '%d seconds', '\\x",
                           userId, session->sessionId, session->sourceIpAddr,
                           (int) (session->expiry - session->established));
            ptr = cmdbuff + strlen(cmdbuff);
            for (idx = 0; idx < session->attributes.length; idx++) {
                (void) sprintf(ptr, "%02x", session->attributes.buffer[idx]);
                ptr += 2;
            }
            (void) sprintf(ptr, "')");

            if (WXDBConnection_Execute(dbconn, cmdbuff) < 0) {
                WXLog_Error("Unexpected error inserting session record: %s",
                            WXDB_GetLastErrorMessage(dbconn));
            }

            (void) sprintf(cmdbuff,
                           "INSERT INTO ngxsessionmgr.access ("
                                "user_id, session_id, source_ipaddr, "
                                "accessed) "
                           "VALUES (%d, '%s', '%s', NOW())",
                           userId, session->sessionId, session->sourceIpAddr);
            if (WXDBConnection_Execute(dbconn, cmdbuff) < 0) {
                WXLog_Error("Unexpected error inserting access record: %s",
                            WXDB_GetLastErrorMessage(dbconn));
            }

            WXFree(cmdbuff);
            WXDBConnectionPool_Return(dbconn);
        }
    }

    /* Update the in-memory hashtable of the sessions manager */
    (void) WXThread_MutexLock(&sessionsLock);
    if (!WXHash_InsertEntry(&sessions, session->sessionId, session,
                            NULL, NULL, WXHash_StrHashFn,
                            WXHash_StrEqualsFn)) {
        WXLog_Error("Failed to record session in global validation cache");
        (void) WXThread_MutexUnlock(&sessionsLock);
        if (GlobalData.dbConnPool != NULL) (void) flushSessionRecord(session);
        (*handler)(conn, NULL, NULL, destURL);
        return;
    }

    /* Note: callback handler must not block, under session lock! */
    (*handler)(conn, session->sessionId, &(session->attributes), destURL);
    (void) WXThread_MutexUnlock(&sessionsLock);

    return;

memfail:
    WXLog_Error("Memory allocation failure on creating session record");
    _destroySession(session);
    (*handler)(conn, NULL, NULL, destURL);
}
