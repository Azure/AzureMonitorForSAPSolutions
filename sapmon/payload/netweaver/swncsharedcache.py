# Payload modules
from const import *
from helper.context import *
from helper.tools import *

import logging
from datetime import datetime
from pyrfc import Connection, CommunicationError

# wait time in between attempts to make an RFC call to SWNC_GET_WORKLOAD_SNAPSHOT and fetch records
CACHE_EXPIRATION_PERIOD = timedelta(minutes=5)

class SwncRfcSharedCache:
    # static / class variables to enforce only one SWNC_GET_WORKLOAD_SNAPSHOT rfc call attempt
    # across all SWNC_GET_WORKLOAD_SNAPSHOT RFC function calls spread across particular SID of SAP Netweaver provider
    _swncRecordsCache= {}

    @staticmethod
    def getSWNCRecordsForSID(tracer: logging.Logger,
                                          logTag: str, 
                                          sapSid: str, 
                                          rfcName: str,
                                          connection: Connection, 
                                          startDateTime: datetime,
                                          endDateTime: datetime,
                                          useSWNCCache: bool
                                          ):
        if (useSWNCCache and sapSid in SwncRfcSharedCache._swncRecordsCache):
            cacheEntry = SwncRfcSharedCache._swncRecordsCache[sapSid]
            if (cacheEntry['expirationDateTime'] > datetime.utcnow()):
                if (cacheEntry['swnc_records']):
                    return cacheEntry['swnc_records']
        swnc_result = None
        try:
            tracer.info("%s executing RFC SWNC_GET_WORKLOAD_SNAPSHOT check for SID: %s",
                         logTag, sapSid)
            swnc_result = connection.call(rfcName, 
                                        READ_START_DATE=startDateTime.date(), 
                                        READ_START_TIME=startDateTime.time(), 
                                        READ_END_DATE=endDateTime.date(), 
                                        READ_END_TIME=endDateTime.time())
            return swnc_result
        except CommunicationError as e:
            tracer.error("[%s] communication error for rfc %s with SID: %s (%s)",
                              logTag, rfcName, sapSid, e, exc_info=True)
            raise
        except Exception as e:
            tracer.error("[%s] Error occured for rfc %s with SID: %s (%s)", 
                              logTag, rfcName, sapSid, e, exc_info=True)
            raise
        finally:
            if swnc_result:
                SwncRfcSharedCache._swncRecordsCache[sapSid] = { 'swnc_records': swnc_result, 'expirationDateTime': datetime.utcnow() + CACHE_EXPIRATION_PERIOD }