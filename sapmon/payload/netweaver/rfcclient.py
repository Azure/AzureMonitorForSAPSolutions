# Python modules
import hashlib
import json
import pytz
import logging
import re
import time
from datetime import datetime, date, timedelta, time, tzinfo, timezone
from dateutil import tz as dateutil_tz
from pandas import DataFrame
from typing import Dict, List
import pandas

# SAP modules
from pyrfc import Connection, ABAPApplicationError, ABAPRuntimeError, LogonError, CommunicationError

from datetime import datetime as dt
from dateutil.tz import *

# abstract base class module
from netweaver.metricclientfactory import NetWeaverMetricClient
from helper.tools import JsonEncoder

# enforce maximum query window size so that we don't accidentally query SAP for huge
# data sets after periods of prolonged downtime/inactivity
MAX_QUERY_LOOKBACK_WINDOW = timedelta(minutes=15)

# known SWNC Workload metric results task id -> text mappings
SAP_TASK_TYPE_MAPPINGS = {
    b'\x01': 'DIALOG',
    b'\x02': 'UPDATE',
    b'\x03': 'SPOOL',
    b'\x04': 'BCKGRD',
    b'\x05': 'ENQUEUE',
    b'\x06': 'BUF.SYN',
    b'\x07': 'AUTOABA',
    b'\x08': 'UPDATE2',
    b'\x0a': 'EXT.PLUGIN',
    b'\x0b': 'AUTOTH',
    b'\x0c': 'RPCTH',
    b'\x0d': 'RFCVMC',
    b'\x0e': 'DDLOG CLEANUP',
    b'\x0f': 'DEL. THCALL',
    b'\x10': 'AUTOJAVA',
    b'\x11': 'LICENCESRV',
    b'\x12': 'AUTOCCMS',
    b'\x15': 'BGRFC SCHEDULER',
    b'\x21': 'OTHER',
    b'\x22': 'DINOGUI',
    b'\x23': 'B.INPUT',
    b'\x65': 'HTTP',
    b'\x66': 'HTTPS',
    b'\x67': 'NNTP',
    b'\x68': 'SMTP',
    b'\x69': 'FTP',
    b'\x6C': 'LCOM',
    b'\x75': 'HTTP/JSP',
    b'\x76': 'HTTPS/JSP',
    b'\xFC': 'ESI',
    b'\xFD': 'FD ALE',
    b'\xFE': 'RFC',
    b'\xFF': 'CPIC',
}

######
# Implementation of NetWeaverMetricClient abstract base class interface that relies on SAP NetWeaver RFC SDK library to
# make NW RFC calls to fetch SMON and SWNC Workload metrics (ST03).
# NOTE:  Assumes user provided RFC SDK has already been downloaded and installed on the client system
#        and that pynwrfc python module has also already been installed with expected environment settings.
#        Attempting to import this file will result in impot of pyrfc, and if any of the above are not true
#        then the import of this file will fail (due to direct pyrfc package references).
######


class NetWeaverRfcClient(NetWeaverMetricClient):
    def __init__(self,
                 tracer: logging.Logger,
                 sapHostName: str,
                 sapSubdomain: str,
                 sapSysNr: str,
                 sapClient: str,
                 sapUsername: str,
                 sapPassword: str,
                 columnFilterList: List[str],
                 serverTimeZone: tzinfo,
                 sapSid: str,
                 sapLogonGroup: str) -> None:
        self.tracer = tracer
        self.sapSid = sapSid
        self.sapHostName = sapHostName
        self.sapSubdomain = sapSubdomain
        self.fqdn = self._getFullyQualifiedDomainName()
        self.sapSysNr = sapSysNr
        self.sapClient = sapClient
        self.sapUsername = sapUsername
        self.sapPassword = sapPassword
        self.columnFilterList = columnFilterList
        self.tzinfo = serverTimeZone
        self.sapLogonGroup = sapLogonGroup
        self.msserv = "36%s" % self.sapSysNr.zfill(2)
        self.rolesFileURL = "https://aka.ms/SAPRolesFile"
        super().__init__(tracer)

    #####
    # public property getter methods
    #####

    @property
    def Hostname(self) -> str:
        return self.sapHostName

    @property
    def InstanceNr(self) -> str:
        return str(self.sapSysNr)

    #####
    # public methods to implement abstract base class interface methods for NetWeaverMetricClient.
    #####

    """
    validate that config settings and that client can establish connection
    """

    def validate(self) -> bool:
        return True

    """
    return tuple of query start / end timestamps that are timezone aware (but in server time)
    so that they can be used to define time range for SMON/SWNC metric queries.  Factor in
    awareness of last run time so that we have some tolerance on small outages or gaps and can be
    used to fill in historical data in those cases, but at same time enforce maximum query window
    to ensure we do not query SAP for huge result sets.
    Also enforce time range logic that ensures start/end time are always the same calendar 'day',
    since that is how SAP stores SMON analysis results
    """

    def getQueryWindow(self,
                       lastRunServerTime: datetime,
                       minimumRunIntervalSecs: int,
                       serverTimeZone: timezone,
                       logTag: str) -> tuple:
        # always start with assumption that query window will work backwards from current system time
        # pass serverTimeZone to calculate UTCOffset based on time zone
        currentServerTime = self.getServerTime(serverTimeZone, logTag)
        # usually a query window will end with the current SAP system time and will have a
        # lookback duration of the minimum check run interval (in seconds)
        # Since SAP requirement is that start and end time must occur on the same calendar day,
        # we must handle special that if default window crosses over the midnight 00:00:00 boundary
        # we will truncate it to terminate at 11:59:59PM
        if lastRunServerTime is None:
            # if there was no previous check timestamp, then we start a new query
            # window that works backwards from the current SAP system time (by the minimum check run interval time).
            # If that will cross the midnight boundary into the previous calendar day,
            # then the start time should be moved up to be 00:00:00 on the current day.
            windowEnd = currentServerTime
            windowStart = currentServerTime - \
                timedelta(seconds=minimumRunIntervalSecs)
            currentMidnight = datetime.combine(
                currentServerTime.date(), time(0, 0, 0), tzinfo=self.tzinfo)
            windowStart = max(windowStart, currentMidnight)
        else:
            # if we have a previous check timestamp to use as the start of new query window,
            # and this new query window will cross this midnight into the next day,
            # then truncate the query window so that it terminates at 11:59:59PM on the current day.
            windowStart = lastRunServerTime + timedelta(seconds=1)
            nextMidnight = datetime.combine(windowStart.date(), time(
                0, 0, 0), tzinfo=self.tzinfo) + timedelta(days=1)
            windowEnd = min(currentServerTime, nextMidnight -
                            timedelta(seconds=1))

        # enforce maximum query window size so that we don't attempt to fetch a huge amount of data
        # if the system has been down for prolonged period of time.  This means that we will
        # never attempt to backfill metric data outside of the MAX_QUERY_LOOKBACK_WINDOW
        if ((windowEnd - windowStart) > MAX_QUERY_LOOKBACK_WINDOW):
            windowStart = windowEnd - MAX_QUERY_LOOKBACK_WINDOW

        self.tracer.info("[%s] getQueryWindow query window for lastRunServerTime: %s, " +
                         "currentServerTime: %s -> [start=%s, end=%s]",
                         logTag,
                         lastRunServerTime,
                         currentServerTime,
                         windowStart,
                         windowEnd)

        return windowStart, windowEnd

    """
    fetch current sap system time stamp and apply the server timezone (if known)
    so that it be used for timezone aware comparisons against tz-aware timestamps
    """

    def getServerTime(self, sapServerTimeZone: timezone, logTag: str) -> datetime:
        self.tracer.info("[%s] executing RFC to get SAP server time", logTag)
        with self._getMessageServerConnection() as connection:
            # read current time from SAP NetWeaver.
            timestampResult = self._rfcGetSystemTime(connection, logTag=logTag)
            systemDateTime = self._parseSystemTimeResult(timestampResult)

            # calculate offset difference by subtratcing dst( daylight savings) difference to the UTC difference value
            if(sapServerTimeZone != None):
                utcOffset = str((sapServerTimeZone['UTCSIGN']) +
                                    str(int(sapServerTimeZone['UTCDIFF'])-int(sapServerTimeZone['DSTDIFF'])))
           
            # check if offset is single digit hour then concatinate '0' for UTC difference 
            # so that string length can be maintianed both for single hour and double digit hour for final seconds calculation for timedelta 
                if(sapServerTimeZone['UTCDIFF'][0:1] == '0'):
                    utcDiff = '0'+utcOffset[1:2]+utcOffset[2:4]+utcOffset[4:6]
                else:
                    utcDiff = utcOffset[0:2]+utcOffset[2:4]+utcOffset[4:6]
            # initialize timzone offset value to tzinfo for the datetime object
                self.tzinfo = timezone(timedelta(hours=int(str('-'+utcDiff[0:2])) if(sapServerTimeZone['UTCSIGN'] == '+') else int(
                    utcDiff[0:2]), minutes=int(utcDiff[2:4]), seconds=int(utcDiff[4:6])))

        return systemDateTime.replace(tzinfo=self.tzinfo)

    """
    fetch  SAP Server time zone and return timezone object
    """

    def getLocalTimeZone(self, logTag: str) -> tzinfo:
        timeZoneResult = None
        with self._getMessageServerConnection() as connection:
            self.tracer.info(
                "[%s] executing RFC /OSP/SYSTEM_TIMEZONE", logTag)
            try:
                rfcName = '/OSP/SYSTEM_TIMEZONE'
                timeZoneResult = connection.call(rfcName)
            #return timezone object with UTCDIFF, UTCSIGN and TimeZone
            except Exception as e:
                self.tracer.error("[%s] Error occured for rfc %s with hostname: %s (%s)",
                                  logTag, rfcName, self.sapHostName, e, exc_info=True)
        return timeZoneResult

    """
    fetch all /SDF/SMON_ANALYSIS_READ metric data and return as a single json string
    """

    def getSmonMetrics(self,
                       startDateTime: datetime,
                       endDateTime: datetime,
                       logTag: str) -> str:
        self.tracer.info(
            "[%s] executing RFC SDF/SMON_ANALYSIS_RUN check", logTag)

        with self._getMessageServerConnection() as connection:
            # get guid to call RFC SDF/SMON_ANALYSIS_READ.
            guidResult = self._rfcGetSmonRunIds(
                connection, startDateTime=startDateTime, endDateTime=endDateTime, logTag=logTag)
            guid = self._parseSmonRunIdsResult(guidResult)

            # based on last run and current time, calculate start and end time.
            #startDate, startTime, _, endTime = self.getNextRunTime(currentDate, currentTime, lastSapRunTime)
            rawResult = self._rfcGetSmonAnalysisByRunId(
                connection, guid, startDateTime=startDateTime, endDateTime=endDateTime, logTag=logTag)
            parsedResult = self._parseSmonAnalysisResults(rawResult, logTag)

            # add additional common metric properties
            self._decorateMetrics('SERVER', 'DATUM', 'TIME', parsedResult)

            return parsedResult

    """
    fetch SWNC_GET_WORKLOAD_SNAPSHOT data, calculate aggregate metrics and return as json string
    """

    def getSwncWorkloadMetrics(self,
                               startDateTime: datetime,
                               endDateTime: datetime,
                               logTag: str) -> str:
        self.tracer.info(
            "[%s] executing RFC SWNC_GET_WORKLOAD_SNAPSHOT check", logTag)
        with self._getMessageServerConnection() as connection:
            snapshotResult = self._rfcGetSwncWorkloadSnapshot(connection,
                                                              startDateTime=startDateTime,
                                                              endDateTime=endDateTime,
                                                              logTag=logTag)

            parsedResult = self._parseSwncWorkloadSnapshotResult(
                snapshotResult, logTag=logTag)

            # add additional common metric properties
            self._decorateSwncWorkloadMetrics(
                parsedResult, queryWindowEnd=endDateTime)

            return parsedResult

    """
    fetch all /SDF/GET_DUMP_LOG metric data and return as a single json string
    """

    def getShortDumpsMetrics(self,
                             startDateTime: datetime,
                             endDateTime: datetime,
                             logTag: str) -> str:
        self.tracer.info("[%s] executing RFC SDF/GET_DUMP_LOG check", logTag)
        parsedResult = []
        with self._getMessageServerConnection() as connection:
            rfcName = '/SDF/GET_DUMP_LOG'
            # get guid to call RFC SDF/GET_DUMP_LOG.
            rawResult = self._rfcCallToFetchLog(
                rfcName, connection, startDateTime=startDateTime, endDateTime=endDateTime, logTag=logTag)
            # check if rawResult if a non-empty list or a NULL value
            if rawResult != None and len(rawResult) > 0:
                parsedResult = self._parseLogResults(
                    rfcName, rawResult, logTag=logTag)
                # add additional common metric properties
                self._decorateMetrics(
                    'E2E_HOST', 'E2E_DATE', 'E2E_TIME', parsedResult)
            return parsedResult

    """
    fetch all /SDF/GET_SYS_LOG metric data and return as a single json string
    """

    def getSysLogMetrics(self,
                         startDateTime: datetime,
                         endDateTime: datetime,
                         logTag: str) -> str:
        self.tracer.info("[%s] executing RFC /SDF/GET_SYS_LOG check", logTag)
        parsedResult = []
        rfcName = '/SDF/GET_SYS_LOG'
        with self._getMessageServerConnection() as connection:
            # get guid to call RFC /SDF/GET_SYS_LOG.
            rawResult = self._rfcCallToFetchLog(
                rfcName, connection, startDateTime=startDateTime, endDateTime=endDateTime, logTag=logTag)
            if rawResult != None and len(rawResult) > 0:
                parsedResult = self._parseLogResults(
                    rfcName, rawResult, logTag=logTag)
                #add additional common metric properties
                self._decorateMetrics(
                    'E2E_HOST', 'E2E_DATE', 'E2E_TIME', parsedResult)
            return parsedResult

    """
    fetch all RFC_READ_TABLE metric data and return as a single json string
    """

    def getFailedUpdatesMetrics(self, logTag: str) -> str:
        self.tracer.info("[%s] executing RFC RFC_READ_TABLE check", logTag)
        parsedResult = []
        rfcName = 'RFC_READ_TABLE'
        with self._getMessageServerConnection() as connection:
            rawResult = self._rfcGetFailedUpdates(connection, logTag=logTag)
            if rawResult != None and len(rawResult) > 0:
                parsedResult = self._parseFailedUpdatesResult(
                    rfcName, rawResult, logTag=logTag)
                # add additional common metric properties
                self._decorateFailedUpdatesMetrics(parsedResult)
            return parsedResult

    """
    fetch all BAPI_XBP_JOB_SELECT metric data and return as a single json string
    """

    def getBatchJobMetrics(self,
                           startDateTime: datetime,
                           endDateTime: datetime,
                           logTag: str) -> str:
        self.tracer.info(
            "[%s] executing RFC BAPI_XBP_JOB_SELECT check", logTag)
        parsedResult = []
        with self._getMessageServerConnection() as connection:
            rawResult = self._rfcGetBatchJob(
                connection, startDateTime=startDateTime, endDateTime=endDateTime, logTag=logTag)
            if rawResult != None and len(rawResult) > 0:
                parsedResult = self._parseBatchJobResult(rawResult, logTag)
                # add additional common metric properties
                self._decorateBatchJobMetrics(parsedResult)
            return parsedResult

    """
    fetch current inbound queues data from TRFC_QIN_GET_CURRENT_QUEUES and return as json string
    """

    def getInboundQueuesMetrics(self, logTag: str) -> str:
        self.tracer.info(
            "[%s] executing RFC TRFC_QIN_GET_CURRENT_QUEUES check", logTag)
        parsedResult = []
        rfcName = "TRFC_QIN_GET_CURRENT_QUEUES"
        with self._getMessageServerConnection() as connection:
            snapshotResult = self._rfcGetCurrentQueuesLog(
                connection, rfcName, logTag=logTag)

            if snapshotResult != None:
                parsedResult = self._parseQueuesAndLockSnapshotResult(
                    rfcName, snapshotResult, "QVIEW")
                self._decorateCurrentQueuesMetrics(parsedResult)

            return parsedResult

    """
    fetch current outbound queues data from TRFC_QOUT_GET_CURRENT_QUEUES and return as json string
    """

    def getOutboundQueuesMetrics(self, logTag: str) -> str:
        self.tracer.info(
            "[%s] executing RFC TRFC_QOUT_GET_CURRENT_QUEUES check", logTag)
        parsedResult = []
        rfcName = "TRFC_QOUT_GET_CURRENT_QUEUES"
        with self._getMessageServerConnection() as connection:
            snapshotResult = self._rfcGetCurrentQueuesLog(
                connection, rfcName, logTag=logTag)

            if snapshotResult != None:
                parsedResult = self._parseQueuesAndLockSnapshotResult(
                    rfcName, snapshotResult, "QVIEW")
                self._decorateCurrentQueuesMetrics(parsedResult)

            return parsedResult

    """
    fetch object lock metrics from ENQUEUE_READ data and return as json string
    """

    def getEnqueueReadMetrics(self, logTag: str, serverTimeZone: timezone) -> str:
        self.tracer.info("[%s] executing RFC ENQUEUE_READ check", logTag)
        rfcName = "ENQUEUE_READ"
        parsedResult = []
        with self._getMessageServerConnection() as connection:
            snapshotResult = self._rfcReadEnqueueLog(connection, logTag=logTag)

            if snapshotResult != None:
                parsedResult = self._parseQueuesAndLockSnapshotResult(
                    rfcName, snapshotResult, "ENQ")
                # initialize self.tzinfo     
                self.getServerTime(serverTimeZone, logTag)    
                
                self._decorateLockMetrics(parsedResult)

            return parsedResult
    #####
    # private methods to initiate RFC connections and fetch server timestamp
    #####

    """
    create fully qualified hostname if subdomain was provided
    """

    def _getFullyQualifiedDomainName(self) -> str:
        if self.sapSubdomain:
            return self.sapHostName + "." + self.sapSubdomain
        else:
            return self.sapHostName

    """
    establish rfc message server connection to sap.
    """

    def _getMessageServerConnection(self) -> Connection:
        # Direct application server logon:  ashost, sysnr
        # load balancing logon:  mshost, msserv, sysid, group
        connection = Connection(  # ashost=self.fqdn,
            sysnr=self.sapSysNr,
            mshost=self.fqdn,
            Group=self.sapLogonGroup,
            msserv=self.msserv,
            ssid=self.sapSid,
            client=self.sapClient,
            user=self.sapUsername,
            passwd=self.sapPassword)
        return connection

    """
    establish rfc connection to sap.
    """

    def _getApplicationServerConnection(self, logTag: str) -> Connection:
        try:
            # Direct application server logon:  ashost, sysnr
            # load balancing logon:  mshost, msserv, sysid, group
            connection = Connection(ashost=self.fqdn,
                                    sysnr=self.sapSysNr,
                                    client=self.sapClient,
                                    user=self.sapUsername,
                                    passwd=self.sapPassword)
            return connection
        except CommunicationError as e:
            #self.tracer.error("[%s] error establishing connection with hostname: %s, sapSysNr: %s, error: %s",
            #                  logTag, self.fqdn, self.sapSysNr, e)
            raise
        except LogonError as e:
            #self.tracer.error("[%s] Incorrect credentials used to connect with hostname: %s username: %s, error: %s",
            #                  logTag, self.fqdn, self.sapUsername, e)
            raise
        except Exception as e:
            #self.tracer.error("[%s] Error occured while establishing connection to hostname: %s, sapSysNr: %s, error: %s ",
            #                  logTag, self.fqdn, self.sapSysNr, e)
            raise

    """
    make RFC call to get system time
    """

    def _rfcGetSystemTime(self, connection: Connection, logTag: str):
        rfcName = 'BDL_GET_CENTRAL_TIMESTAMP'
        timestampResult = None

        try:
            timestampResult = connection.call(rfcName)
            return timestampResult
        except CommunicationError as e:
            self.tracer.error("[%s] communication error for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.fqdn, e, exc_info=True)
        except Exception as e:
            self.tracer.error("[%s] Error occured for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.fqdn, e, exc_info=True)

        return None

    """
    parse system date and time fields from RFC response and return as a datetime.
    The RFC res[pmse will not have any timezone identifier, so we will apply the known
    server time zone provided by the caller when the client was created
    """

    def _parseSystemTimeResult(self, result: Dict[str, str]) -> datetime:
        if result is None:
            raise ValueError(
                "Invalid result received from BDL_GET_CENTRAL_TIMESTAMP")

        currentSystemDate: date = None
        currentSystemTime: time = None

        if 'TAG' in result:
            currentSystemDate = datetime.strptime(
                result['TAG'], '%Y%m%d').date()
        else:
            raise ValueError(
                "RFC BDL_GET_CENTRAL_TIMESTAMP result does not have TAG value: %s" % result)

        if 'UHRZEIT' in result:
            currentSystemTime = datetime.strptime(
                result['UHRZEIT'], '%H%M%S').time()
        else:
            raise ValueError(
                "RFC BDL_GET_CENTRAL_TIMESTAMP result does not have UHRZEIT value: %s" % result)

        return datetime.combine(date=currentSystemDate, time=currentSystemTime, tzinfo=self.tzinfo)

    """
    helper to take seperate server Date and Time fields and return a datetime
    object with server timezone applied
    """

    def _datetimeFromDateAndTimeString(self, dateStr: str, timeStr: str) -> datetime:
        # expecte dateStr to have format %Y%m%d
        # expect timeStr to have format %H%M%S
        parsedDateTime = datetime.strptime(
            dateStr + ' ' + timeStr, '%Y%m%d %H%M%S')
      
        # get UTCOffset for parsedDateTime(SAP servertime)
        # initialize parsedDateTime by extending timezone with UTC   
        parsedServerDateTime = parsedDateTime.replace(tzinfo=tzoffset("UTC+0",0))
       
       # apply time zone offset with timedelta in seconds saved in self.tzinfo
        if(self.tzinfo != None):
            sapServerUTCDateTime = parsedServerDateTime.astimezone(tzoffset("UTC",self.tzinfo.utcoffset(None)))
        else:
            return parsedServerDateTime
        return sapServerUTCDateTime
      

    #####
    # private methods to perform two-phase call to first fetch most recent SMON run analysis identifier (guid)
    # and then use that identifer to make a second call to fetch the full SMON analysis result set for that ID.
    # Also methods to parse the responses from those RFC calls and to decorate metric results.
    #####

    """
    make RFC call to fetch list of SDF/SMON snapshot identifiers in the given time range
    """

    def _rfcGetSmonRunIds(self,
                          connection: Connection,
                          startDateTime: datetime,
                          endDateTime: datetime,
                          logTag: str):
        rfcName = '/SDF/SMON_GET_SMON_RUNS'

        self.tracer.info("[%s] invoking rfc %s for hostname=%s with from_date=%s, to_date=%s",
                         logTag,
                         rfcName,
                         self.sapHostName,
                         startDateTime.date(),
                         endDateTime.date())

        try:
            smon_result = connection.call(
                rfcName, FROM_DATE=startDateTime.date(), TO_DATE=endDateTime.date())
            return smon_result
        except CommunicationError as e:
            self.tracer.error("[%s] communication error for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)
        except Exception as e:
            self.tracer.error("[%s] Error occured for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)

        return None

    """
    parse result from /SDF/SMON_GET_SMON_RUNS and return Run ID GUID.
    """

    def _parseSmonRunIdsResult(self, result):
        if 'SMON_RUNS' in result:
            if (len(result['SMON_RUNS']) == 0):
                raise ValueError("SMON_RUNS result list was empty!")
            if 'GUID' in result['SMON_RUNS'][0]:
                return result['SMON_RUNS'][0]['GUID']
            else:
                raise ValueError(
                    "GUID value does not exist in /SDF/SMON_GET_SMON_RUNS return result.")
        else:
            raise ValueError(
                "SMON_RUNS value does not exist in /SDF/SMON_GET_SMON_RUNS return result.")

    """
    call RFC SDF/SMON_ANALYSIS_RUN to lookup analysis results for specific Run ID and return the result
    """

    def _rfcGetSmonAnalysisByRunId(self,
                                   connection: Connection,
                                   guid: str,
                                   startDateTime: datetime,
                                   endDateTime: datetime,
                                   logTag: str):
        rfcName = '/SDF/SMON_ANALYSIS_READ'
        result = None

        if not guid:
            raise ValueError(("argument error for rfc %s for hostname: %s, guid: %s, "
                              "expected start (%s) and end time (%s) to be same day")
                             % (rfcName, self.sapHostName, guid, startDateTime, endDateTime))

        # validate that start and end time are the same day, since thaty is what RFC expects
        if (startDateTime.date() != endDateTime.date()):
            raise ValueError(("argument error for rfc %s for hostname: %s, guid: %s, "
                              "expected start (%s) and end time (%s) to be same day")
                             % (rfcName, self.sapHostName, guid, startDateTime, endDateTime))

        self.tracer.info("[%s] invoking rfc %s for hostname=%s with guid=%s, datum=%s, start_time=%s, end_time=%s",
                         logTag,
                         rfcName,
                         self.sapHostName,
                         guid,
                         startDateTime.date(),
                         startDateTime.time(),
                         endDateTime.time())

        try:
            result = connection.call(rfcName,
                                     GUID=guid,
                                     DATUM=startDateTime.date(),
                                     START_TIME=startDateTime.time(),
                                     END_TIME=endDateTime.time())
            return result
        except CommunicationError as e:
            self.tracer.error("[%s] communication error for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)
        except Exception as e:
            self.tracer.error("[%s] Error occured for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)

        return None

    """
    return header information from sdf/smon_analysis_read
    """

    def _parseSmonAnalysisResults(self, result, logTag: str):
        rfcName = 'SDF/SMON_ANALYSIS_READ'
        if result is None:
            raise ValueError("empty result received for rfc %s for hostname: %s" % (
                rfcName, self.sapHostName))

        processedResult = None
        if 'HEADER' in result:
            # create new dictionary with only values from filterList if filter dictionary exists.
            processedResult = result['HEADER']
            self.tracer.info("[%s] rfc %s returned %d records from hostname: %s",
                             logTag, rfcName, len(processedResult), self.sapHostName)

            # for each item in the list, create a new dictionary.
            if self.columnFilterList:
                filteredResult = list()
                for record in processedResult:
                    filteredRow = {columnName: record[columnName]
                                   for columnName in self.columnFilterList}
                    filteredResult.append(filteredRow)
                processedResult = filteredResult
        else:
            raise ValueError("%s result does not contain HEADER key from hostname: %s" % (
                rfcName, self.sapHostName))

        return processedResult

    #####
    # private methods to make SWNC Workload snapshot call, parse results and return enriched ST03 metrics results
    #####

    """
    call RFC SWNC_GET_WORKLOAD_SNAPSHOT and return result records
    """

    def _rfcGetSwncWorkloadSnapshot(self,
                                    connection: Connection,
                                    startDateTime: datetime,
                                    endDateTime: datetime,
                                    logTag: str):
        rfcName = 'SWNC_GET_WORKLOAD_SNAPSHOT'

        self.tracer.info(("[%s] invoking rfc %s for hostname=%s with read_start_date=%s, read_start_time=%s, "
                          "read_end_date=%s, read_end_time=%s"),
                         logTag,
                         rfcName,
                         self.sapHostName,
                         startDateTime.date(),
                         startDateTime.time(),
                         endDateTime.date(),
                         endDateTime.time())

        try:
            swnc_result = connection.call(rfcName,
                                          READ_START_DATE=startDateTime.date(),
                                          READ_START_TIME=startDateTime.time(),
                                          READ_END_DATE=endDateTime.date(),
                                          READ_END_TIME=endDateTime.time())
            return swnc_result
        except CommunicationError as e:
            self.tracer.error("[%s] communication error for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)
        except Exception as e:
            self.tracer.error("[%s] Error occured for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)

        return None

    """
    check for empty results from RFC calls
    records is a list of records in TASKTIMES  
    server_result_records is a list of errors in SERVER_RECS_RETURN_ERRORS
    TASKTIMES and SERVER_RECS_RETURN_ERRORS are part of result from RFC call
    """

    def _isRFCRecordEmpty(self, rfcName, records, server_result_records, logTag):
        for error in server_result_records:
            self.tracer.info(("%s RFC Name: %s, System ID: %s, Instance: %s, Error: %s"),
                             logTag, rfcName, error["SYSTEMID"], error["INSTANCE"], error["ERROR_TEXT"])

        if (len(records) == 0):
            self.tracer.info(
                ("%s No records were found for rfc %s with hostname %s"), logTag, rfcName, self.sapHostName)
            return True
        return False

    """
    parse results from SWNC_GET_WORKLOAD_SNAPSHOT and enrich with additional calculated ST03 properties
    """

    def _parseSwncWorkloadSnapshotResult(self, result, logTag: str):
        rfcName = 'SWNC_GET_WORKLOAD_SNAPSHOT'
        if result is None:
            raise ValueError("empty result received for rfc %s from hostname: %s"
                             % (rfcName, self.sapHostName))

        def GetKeyValue(dictionary, key):
            if key not in dictionary:
                raise ValueError("Result received for rfc %s from hostname: %s does not contain key: %s"
                                 % (rfcName, self.sapHostName, key))
            return dictionary[key]

        records = GetKeyValue(result, 'TASKTIMES')
        server_result_records = GetKeyValue(
            result, 'SERVER_RECS_RETURN_ERRORS')
        processed_results = list()

        if self._isRFCRecordEmpty(rfcName, records, server_result_records, logTag=logTag):
            return processed_results

        for record in records:
            # try to map task type hex code to more descriptive task name to make more readable, but
            # if we can't find a mapping then just echo the taskTypeId
            taskTypeId = GetKeyValue(record, 'TASKTYPE')
            taskTypeText = (SAP_TASK_TYPE_MAPPINGS[taskTypeId]
                            if taskTypeId in SAP_TASK_TYPE_MAPPINGS
                            else taskTypeId)

            processed_result = {
                "Task Type": taskTypeId,
                "Task Type Name": taskTypeText,
                "Total Steps": GetKeyValue(record, 'COUNT'),
                "Total Response Time": GetKeyValue(record, 'RESPTI'),
                "Total Processing Time": GetKeyValue(record, 'PROCTI'),
                "Total CPU Time": GetKeyValue(record, 'CPUTI'),
                "Total Queue Time": GetKeyValue(record, 'QUEUETI'),
                "Total Roll Wait Time": GetKeyValue(record, 'ROLLWAITTI'),
                "Total GUI Steps": GetKeyValue(record, 'GUICNT'),
                "Total GUI Time": GetKeyValue(record, 'GUITIME'),
                "Total GUI Net Time": GetKeyValue(record, 'GUINETTIME'),
                "Total DB Time": GetKeyValue(record, 'READSEQTI') + GetKeyValue(record, 'CHNGTI') + GetKeyValue(record, 'READDIRTI'),
                "Total DB Dir Read Time": GetKeyValue(record, 'READDIRTI'),
                "Total DB Seq Read Time": GetKeyValue(record, 'READSEQTI'),
                "Total DB Chg Time": GetKeyValue(record, 'CHNGTI'),
                "Total DB Proc Time": GetKeyValue(record, 'DBP_TIME'),
                "Total DB Proc Steps": GetKeyValue(record, 'DBP_COUNT'),
                "Total DB Dir Read Steps": GetKeyValue(record, 'READDIRCNT'),
                "Total DB Seq Read Steps": GetKeyValue(record, 'READSEQCNT'),
                "Total DB Change Steps": GetKeyValue(record, 'CHNGCNT'),
                "PHYREADCNT": GetKeyValue(record, 'PHYREADCNT'),
                "PHYCHNGREC": GetKeyValue(record, 'PHYCHNGREC'),
                "PHYCALLS": GetKeyValue(record, 'PHYCALLS'),
            }

            # ST03 - Average response time across all steps
            if (GetKeyValue(record, 'COUNT') != 0):
                processed_result['ST03_Avg_Resp_Time'] = GetKeyValue(
                    record, 'RESPTI') / GetKeyValue(record, 'COUNT')
            else:
                processed_result['ST03_Avg_Resp_Time'] = 0.0

            # ST03 - CPU Time, Processing Time, Queue, Roll Wait and DB times as % of Response Time
            if (GetKeyValue(record, 'RESPTI') != 0):
                processed_result['ST03_CPU_Time'] = GetKeyValue(
                    record, 'CPUTI') / GetKeyValue(record, 'RESPTI')
                processed_result['ST03_Processing_Time'] = GetKeyValue(
                    record, 'PROCTI') / GetKeyValue(record, 'RESPTI')
                processed_result['ST03_DB_Time'] = processed_result['Total DB Time'] / \
                    GetKeyValue(record, 'RESPTI')
                processed_result['ST03_Queue_Time'] = GetKeyValue(
                    record, 'QUEUETI') / GetKeyValue(record, 'RESPTI')
                processed_result['ST03_RollWait_Time'] = GetKeyValue(
                    record, 'ROLLWAITTI') / GetKeyValue(record, 'RESPTI')
            else:
                processed_result['ST03_CPU_Time'] = 0.0
                processed_result['ST03_Processing_Time'] = 0.0
                processed_result['ST03_DB_Time'] = 0.0
                processed_result['ST03_Queue_Time'] = 0.0
                processed_result['ST03_RollWait_Time'] = 0.0

            # ST03 - Average DB direct read latency
            if (GetKeyValue(record, 'READDIRCNT') != 0):
                processed_result['ST03_Avg_DB_Dir_Time'] = GetKeyValue(
                    record, 'READDIRTI') / GetKeyValue(record, 'READDIRCNT')
            else:
                processed_result['ST03_Avg_DB_Dir_Time'] = 0.0

            # ST03 - Average DB sequential read latency
            if (GetKeyValue(record, 'READSEQCNT') != 0):
                processed_result['ST03_Avg_DB_Seq_Time'] = GetKeyValue(
                    record, 'READSEQTI') / GetKeyValue(record, 'READSEQCNT')
            else:
                processed_result['ST03_Avg_DB_Seq_Time'] = 0.0

            # ST03 - Average DB change latency
            if (GetKeyValue(record, 'CHNGCNT') != 0):
                processed_result['ST03_Avg_DB_Change_Time'] = GetKeyValue(
                    record, 'CHNGTI') / GetKeyValue(record, 'CHNGCNT')
            else:
                processed_result['ST03_Avg_DB_Change_Time'] = 0.0

            # ST03 - Average DB Procedure latency
            if (GetKeyValue(record, 'DBP_COUNT') != 0):
                processed_result['ST03_Avg_DB_Procedure_Time'] = GetKeyValue(
                    record, 'DBP_TIME') / GetKeyValue(record, 'DBP_COUNT')
            else:
                processed_result['ST03_Avg_DB_Procedure_Time'] = 0.0

            processed_results.append(processed_result)

        return processed_results

    """
    take parsed SWNC result set and decorate each record with additional fixed set of 
    properties needed for metrics records
    """

    def _decorateSwncWorkloadMetrics(self, records: list, queryWindowEnd: datetime) -> None:
        currentTimestamp = datetime.now(timezone.utc)

        for record in records:
            # swnc workload metrics are aggregated across the SID, so no need to include hostname/instance/subdomain dimensions
            record['timestamp'] = currentTimestamp
            # apply timezone and offset to utc
            # get UTCOffset for parsedDateTime(SAP servertime)
            # initialize parsedDateTime by applying UTC timezone
            if(self.tzinfo != None):
                queryWindowEndServerTime = queryWindowEnd.replace(tzinfo=tzoffset("UTC+0", 0))
                # apply time zone offset with timedelta in seconds saved in self.tzinfo
                queryWindowEndUTCDateTime = queryWindowEndServerTime.astimezone(tzoffset("UTC", self.tzinfo.utcoffset(None)))
                record['serverTimestamp'] = queryWindowEndUTCDateTime
            else:
                record['serverTimestamp'] = queryWindowEnd
            record['SID'] = self.sapSid
            record['client'] = self.sapClient

    """
    make common RFC call for GET_DUMP_LOG & GET_SYS_LOG and return result records
    """

    def _rfcCallToFetchLog(self,
                           rfcName: str,
                           connection: Connection,
                           startDateTime: datetime,
                           endDateTime: datetime,
                           logTag: str):

        if rfcName not in ["/SDF/GET_DUMP_LOG", "/SDF/GET_SYS_LOG"]:
            raise ValueError("Incorrect RFC name passed %s", rfcName)

        self.tracer.info("[%s] invoking rfc %s for hostname=%s with date_from=%s, time_from=%s, date_to=%s, time_to=%s",
                         logTag,
                         rfcName,
                         self.sapHostName,
                         startDateTime.date(),
                         startDateTime.time(),
                         endDateTime.date(),
                         endDateTime.time())
        try:
            rfc_call_result = connection.call(rfcName,
                                              DATE_FROM=startDateTime.date(),
                                              TIME_FROM=startDateTime.time(),
                                              DATE_TO=endDateTime.date(),
                                              TIME_TO=endDateTime.time())

            return rfc_call_result
        except CommunicationError as e:
            self.tracer.error("[%s] communication error for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)

        except ABAPApplicationError as e:
            # handle NO DATA FOUND exception to return an empty list
            if e.key == "NO_DATA_FOUND":
                self.tracer.info("[%s] Exception raised for rfc %s with hostname: %s (%s)",
                                 logTag, rfcName, self.sapHostName, e.key, exc_info=True)
                return []
            self.tracer.error("[%s] Exception raised for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)

        except Exception as e:
            self.tracer.error("[%s] Error occured for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)

        return None

    """
    common method to return header information from /SDF/GET_DUMP_LOG and /SDF/GET_SYS_LOG
    """

    def _parseLogResults(self, rfcName, result, logTag):
        if result is None:
            raise ValueError("empty result received for rfc %s for hostname: %s" % (
                rfcName, self.sapHostName))
        colNames = None
        processedResult = None
        if 'ES_E2E_LOG_STRUCT_DESC' in result:
            # create new dictionary with only values from filterList if filter dictionary exists.
            colNames = result['ES_E2E_LOG_STRUCT_DESC']
            self.tracer.info("[%s] rfc %s returned %d records from hostname: %s",
                             logTag, rfcName, len(colNames), self.sapHostName)
        else:
            raise ValueError("%s result does not contain ES_E2E_LOG_STRUCT_DESC key from hostname: %s" % (
                rfcName, self.sapHostName))

        if 'ET_E2E_LOG' in result:
            # create new dictionary with only values from filterList if filter dictionary exists.
            processedResult = result['ET_E2E_LOG']
            self.tracer.info("[%s] rfc %s returned %d records from hostname: %s",
                             logTag, rfcName, len(processedResult), self.sapHostName)
        else:
            raise ValueError("%s result does not contain ET_E2E_LOG key from hostname: %s" % (
                rfcName, self.sapHostName))

        processedResult = self._renameColumnNames(processedResult, colNames)
        return processedResult

    """
    common method for RFC calls /SDF/GET_DUMP_LOG and /SDF/GET_SYS_LOG to rename the column name with meaningful 
    name returned by SAP in a different table
    """

    def _renameColumnNames(self, records: list, colNames) -> list:
       dataframe = DataFrame(records, columns=['E2E_DATE', 'E2E_TIME', 'E2E_USER', 'E2E_SEVERITY', 'E2E_HOST',
                                               'FIELD1', 'FIELD2', 'FIELD3', 'FIELD4', 'FIELD5', 'FIELD6', 'FIELD7',
                                               'FIELD8', 'FIELD9'])
       dataframe.rename(columns={"FIELD1": colNames["FIELD1"],
                                 "FIELD2": colNames["FIELD2"],
                                 "FIELD3": colNames["FIELD3"],
                                 "FIELD4": colNames["FIELD4"],
                                 "FIELD5": colNames["FIELD5"],
                                 "FIELD6": colNames["FIELD6"],
                                 "FIELD7": colNames["FIELD7"],
                                 "FIELD8": colNames["FIELD8"],
                                 "FIELD9": colNames["FIELD9"]},
                        inplace=True, errors='raise')
       return dataframe.to_dict('records')

    """
    common method take parsed result set and decorate each record with additional fixed set of 
    properties expected for metrics records
    """

    def _decorateMetrics(self, tableName, dateCol, timeCol, records: list) -> None:
        currentTimestamp = datetime.now(timezone.utc)

        # "dateCol": column name with date value - E.g : "20210329",
        # "timeCol": column name with time value - E.g : "121703",
        # "tableName":  column name with value similar to "sapsbx00_MSX_30"

        # regex to extract hostname / SID / instance from SERVER property, since
        # every short dump analysis record will contain host/instances across the
        # entire SAP landscape
        serverRegex = re.compile(
            r"(?P<hostname>.+?)_(?P<SID>[^_]+)_(?P<instanceNr>[0-9]+)")

        for record in records:
            # parse DATUM/TIME fields into serverTimestamp
            record['serverTimestamp'] = self._datetimeFromDateAndTimeString(
                record[dateCol], record[timeCol])

            # parse SERVER field into hostname/SID/InstanceNr properties
            m = serverRegex.match(record[tableName])
            if m:
                fields = m.groupdict()
                record['hostname'] = fields['hostname']
                record['SID'] = fields['SID']
                record['instanceNr'] = fields['instanceNr']
            else:
                self.tracer.error(
                    "record had unexpected SERVER format: %s", record[tableName])
                record['hostname'] = ''
                record['SID'] = ''
                record['instanceNr'] = ''

            record['client'] = self.sapClient
            record['subdomain'] = self.sapSubdomain
            record['timestamp'] = currentTimestamp

    """
    method take parsed result set for batch jobs and decorate each record with additional fixed set of 
    properties expected for metrics records
    """

    def _decorateBatchJobMetrics(self, records: list) -> None:
        currentTimestamp = datetime.now(timezone.utc)

        # regex to extract hostname / SID / instance from SERVER property
        serverRegex = re.compile(
            r"(?P<hostname>.+?)_(?P<SID>[^_]+)_(?P<instanceNr>[0-9]+)")

        for record in records:
            if self._isStringNullOrWhitespace(record['STRTDATE']) and self._isStringNullOrWhitespace(record['STRTTIME']):
                # parse actual start datetime STRTDATE/STRTTIME fields into serverTimestamp
                record['serverTimestamp'] = self._datetimeFromDateAndTimeString(
                    record['STRTDATE'], record['STRTTIME'])
            # if actual start date/time is empty use scheduled/planned start datetime
            elif self._isStringNullOrWhitespace(record['SDLSTRTDT']) and self._isStringNullOrWhitespace(record['SDLSTRTTM']):
                # parse scheduled start date/time SDLSTRTDT/SDLSTRTTM fields into serverTimestamp
                record['serverTimestamp'] = self._datetimeFromDateAndTimeString(
                    record['SDLSTRTDT'], record['SDLSTRTTM'])
            else:
                raise ValueError("Error occured in batch job rfc - 'BAPI_XBP_JOB_SELECT'. %s - SDLSTRTDT : %s or SDLSTRTTM : %s is empty",
                                 record['SDLSTRTDT'], record['SDLSTRTTM'])

            # parse SERVER field into hostname/SID/InstanceNr properties
            if self._isStringNullOrWhitespace(record['REAXSERVER']) and self._isStringNullOrWhitespace(record['REAXSERVER']):
                m = serverRegex.match(record['REAXSERVER'])
                if m:
                    fields = m.groupdict()
                    record['hostname'] = fields['hostname']
                    record['SID'] = fields['SID']
                    record['instanceNr'] = fields['instanceNr']
                else:
                    self.tracer.error(
                        "[%s] record had unexpected SERVER format: %s", record['REAXSERVER'])
                    self._setHostSidInstanceEmpty(record)
            else:
                self.tracer.error("'REAXSERVER' record is empty")
                self._setHostSidInstanceEmpty(record)

            record['client'] = self.sapClient
            record['subdomain'] = self.sapSubdomain
            record['timestamp'] = currentTimestamp

    """
    common method check if the passed in string is not None and it does not contain only whitespaces.
    """

    def _isStringNullOrWhitespace(self, inputValue: str):
        if inputValue != None and len(inputValue.strip()) > 0:
            return True
        return False

    """
    common method set hostname, sid and instanceNr as empty when the SAP returns empty value for 'Server' info column
    """

    def _setHostSidInstanceEmpty(self, record: list):
        record['hostname'] = ''
        record['SID'] = ''
        record['instanceNr'] = ''

    """
    method take parsed result set for failedupdates and decorate each record with additional fixed set of 
    properties expected for metrics records
    """

    def _decorateFailedUpdatesMetrics(self, records: list) -> None:
        currentTimestamp = datetime.now(timezone.utc)
        # regex to extract hostname / SID / instance from SERVER property, since
        # every short dump analysis record will contain host/instances across the
        # entire SAP landscape
        serverRegex = re.compile(
            r"(?P<hostname>.+?)_(?P<SID>[^_]+)_(?P<instanceNr>[0-9]+)")

        for record in records:
            # record['VBDATE'] contains date and time value combined in one string
            # below code is used to extract the first 8 char for date and rest for time
            if record['VBDATE'] != None and len(record['VBDATE']) > 0:
                startdate = record['VBDATE'][0:8]
                enddate = record['VBDATE'][8:len(record['VBDATE'])]

            # parse DATUM/TIME fields into serverTimestamp
            record['serverTimestamp'] = self._datetimeFromDateAndTimeString(
                startdate, enddate)

            # parse SERVER field into hostname/SID/InstanceNr properties
            m = serverRegex.match(record['VBCLINAME'])
            if m:
                fields = m.groupdict()
                record['hostname'] = fields['hostname']
                record['SID'] = fields['SID']
                record['instanceNr'] = fields['instanceNr']
            else:
                self.tracer.error(
                    "[%s] record had unexpected SERVER format: %s", record['VBCLINAME'])
                record['hostname'] = ''
                record['SID'] = ''
                record['instanceNr'] = ''

            record['client'] = self.sapClient
            record['subdomain'] = self.sapSubdomain
            record['timestamp'] = currentTimestamp

    """
    call RFC RFC_READ_TABLE and return result records
    """

    def _rfcGetFailedUpdates(self, connection: Connection, logTag: str):
        rfcName = 'RFC_READ_TABLE'

        self.tracer.info(("[%s] invoking rfc %s for hostname=%s with CALL_MODE = 2"),
                         logTag,
                         rfcName,
                         self.sapHostName)

        try:
            faileupdates_result = connection.call(rfcName,
                                                  QUERY_TABLE='VBHDR',
                                                  DELIMITER=';')
            return faileupdates_result
        except CommunicationError as e:
            self.tracer.error("[%s] communication error for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)

        except ABAPApplicationError as e:
            # handle NO DATA FOUND exception to return an empty list
            if e.key == "TABLE_WITHOUT_DATA":
                self.tracer.info("[%s] Exception raised for rfc %s with hostname: %s (%s)",
                                 logTag, rfcName, self.sapHostName, e.key, exc_info=True)
                return []
            elif e.key == "TABLE_NOT_AVAILABLE":
                self.tracer.error("[%s] Exception raised for rfc %s with hostname: %s (%s)",
                                  logTag, rfcName, self.sapHostName, e, exc_info=True)

        except ABAPRuntimeError as e:
            self.tracer.error("[%s] Runtime error for rfc %s with hostname: %s (%s). Update the roles in SAP System using role file %s",
                              logTag, rfcName, self.sapHostName, e, self.rolesFileURL, exc_info=True)

        except Exception as e:
            self.tracer.error("[%s] Error occured for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)

        return None

    """
    parse results from RFC_READ_TABLE and enrich with additional calculated Failed Updates properties
    """

    def _parseFailedUpdatesResult(self, rfcName, result, logTag):
        if result is None:
            raise ValueError("empty result received for rfc %s from hostname: %s"
                             % (rfcName, self.sapHostName))

        def GetKeyValue(dictionary, key):
            if key not in dictionary:
                raise ValueError("Result received for rfc %s from hostname: %s does not contain key: %s"
                                 % (rfcName, self.sapHostName, key))
            return dictionary[key]

        colNames = None
        processedResult = None
        if 'FIELDS' in result:
            # create new dictionary with only values from filterList if filter dictionary exists.
            records = GetKeyValue(result, 'FIELDS')
            colNames = [sub['FIELDNAME'] for sub in records]
            self.tracer.info("[%s] rfc %s returned %d records from hostname: %s",
                             logTag, rfcName, len(colNames), self.sapHostName)
        else:
            raise ValueError("%s result does not contain FIELDS key from hostname: %s" % (
                rfcName, self.sapHostName))

        if 'DATA' in result:
            # create new dictionary with only values from filterList if filter dictionary exists.
            dataResult = result['DATA']
            self.tracer.info("[%s] rfc %s returned %d records from hostname: %s",
                             logTag, rfcName, len(dataResult), self.sapHostName)
            processedResult = self._processDataResults(dataResult, colNames)
        else:
            raise ValueError("%s result does not contain DATA key from hostname: %s" % (
                rfcName, self.sapHostName))
        return processedResult

    """
    Function to parse the raw data result we get back into SAP and extract the column values mapping to the FEILDS table
    Sample Raw Result : "{'WA': '3DA7EF6910480030E00611BB5179B775;001;'}"
    """

    def _processDataResults(self, result, colNames):
        processedDataList = list()
        processedResult = None
        if result != None and len(result) > 0:
            # parse through each row returned in the result
            for record in result:
                # extract just the data part belonging to the FEILDS column by split string function
                processedResult = str(record).split(":")
                if processedResult != None and len(processedResult) > 0:
                    # Remove additional characters e.g {, }, '
                    processedResult = processedResult[1].replace(
                        "'", "").replace("}", "")
                    # Remove the empty characters in the string using strip function and then split the string to
                    # extract each value as a different column value
                    processedResult = [x.strip()
                                       for x in processedResult.split(';')]
                    # colNames - contains the name of the key and processedResult contains the values
                    # failedUpdateDic - dict with key and values
                    failedUpdateDic = dict(zip(colNames, processedResult))
                    processedDataList.append(failedUpdateDic)
        return processedDataList

    """
    RFC call for BAPI_XBP_JOB_SELECT and return result records
    """

    def _rfcGetBatchJob(self,
                        connection: Connection,
                        startDateTime: datetime,
                        endDateTime: datetime,
                        logTag: str):
        rfcName = "BAPI_XBP_JOB_SELECT"
        self.tracer.info("[%s] invoking rfc %s for hostname=%s with date_from=%s, time_from=%s, date_to=%s, time_to=%s",
                         logTag,
                         rfcName,
                         self.sapHostName,
                         startDateTime.date(),
                         startDateTime.time(),
                         endDateTime.date(),
                         endDateTime.time())

        jobSelectParam = {'JOBNAME': '*', 'USERNAME': '*', 'FROM_DATE': startDateTime.date(
        ), 'FROM_TIME': startDateTime.time(), 'TO_DATE': endDateTime.date(), 'TO_TIME': endDateTime.time()}
        try:
            self._rfcCallLogonJob(connection, logTag=logTag)

            rfc_call_result = connection.call(rfcName,
                                              EXTERNAL_USER_NAME=self.sapUsername,
                                              JOB_SELECT_PARAM=jobSelectParam)

            return rfc_call_result
        except CommunicationError as e:
            self.tracer.error("[%s] communication error for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)
        except ABAPRuntimeError as e:
            self.tracer.error("[%s] Runtime error for rfc %s with hostname: %s (%s). Update the roles in SAP System using role file %s",
                              logTag, rfcName, self.sapHostName, e, self.rolesFileURL, exc_info=True)
        except Exception as e:
            self.tracer.error("[%s] Error occured for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)

        return None

    """
    RFC call for BAPI_XMI_LOGON and return result records
    """

    def _rfcCallLogonJob(self,
                         connection: Connection,
                         logTag: str):
        rfcName = "BAPI_XMI_LOGON"
        self.tracer.info("[%s] invoking rfc %s for hostname=%s",
                         logTag,
                         rfcName,
                         self.sapHostName)

        try:
            rfc_call_result = connection.call(rfcName,
                                              EXTCOMPANY='TESTC',
                                              EXTPRODUCT='TESTP',
                                              INTERFACE='XBP',
                                              VERSION='3.0')

            return rfc_call_result
        except CommunicationError as e:
            self.tracer.error("[%s] communication error for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)
            raise
        except ABAPRuntimeError as e:
            self.tracer.error("[%s] Runtime error for rfc %s with hostname: %s (%s). Update the roles in SAP System using role file %s",
                              logTag, rfcName, self.sapHostName, e, self.rolesFileURL, exc_info=True)
            raise
        except Exception as e:
            self.tracer.error("[%s] Error occured for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)
            raise

    """
    return header information from BAPI_XBP_JOB_SELECT
    """

    def _parseBatchJobResult(self, result, logTag):
        rfcName = 'BAPI_XBP_JOB_SELECT'
        if result is None:
            raise ValueError("empty result received for rfc %s for hostname: %s" % (
                rfcName, self.sapHostName))

        processedResult = None
        if 'JOB_HEAD' in result:
            # create new dictionary with only values from filterList if filter dictionary exists.
            processedResult = result['JOB_HEAD']
            self.tracer.info("[%s] rfc %s returned %d records from hostname: %s",
                             logTag, rfcName, len(processedResult), self.sapHostName)
        else:
            raise ValueError("%s result does not contain JOB_HEAD key from hostname: %s" % (
                rfcName, self.sapHostName))

        return processedResult

    """
    call RFC TRFC_QIN_GET_CURRENT_QUEUES/TRFC_QOUT_GET_CURRENT_QUEUES
    and return all current existing queues.
    """

    def _rfcGetCurrentQueuesLog(self, connection: Connection, rfcName, logTag):

        self.tracer.info(("[%s] invoking rfc %s for hostname=%s for client %s"),
                         logTag,
                         rfcName,
                         self.sapHostName,
                         self.sapClient)

        try:
            queues_result = connection.call(rfcName, CLIENT=self.sapClient)
            return queues_result
        except CommunicationError as e:
            self.tracer.error("[%s] communication error for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)
        except ABAPRuntimeError as e:
            self.tracer.error("[%s] Runtime error for rfc %s with hostname: %s (%s). Update the roles in SAP System using role file %s",
                              logTag, rfcName, self.sapHostName, e, self.rolesFileURL, exc_info=True)
        except Exception as e:
            self.tracer.error("[%s] Error occured for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)

        return None

    """
    parse results from ENQUEUE_READ/TRFC_QIN_GET_CURRENT_QUEUES/TRFC_QOUT_GET_CURRENT_QUEUES 
    and enrich with additional properties
    """

    def _parseQueuesAndLockSnapshotResult(self, rfcName, result, tableName):
        if result is None:
            raise ValueError("empty result received for rfc %s from hostname: %s"
                             % (rfcName, self.sapHostName))
        processed_results = list()
        records = result[tableName]
        for record in records:
            processed_results.append(record)
        return processed_results

    """
    take parsed TRFC_QIN_GET_CURRENT_QUEUES/TRFC_QOUT_GET_CURRENT_QUEUES result set
    and decorate each record with additional fixed set of  properties needed for metrics records
    """

    def _decorateCurrentQueuesMetrics(self, records: list) -> None:
        for record in records:
            record['SID'] = self.sapSid
            record['client'] = record['MANDT']
            record['subdomain'] = self.sapSubdomain
            record['instanceNr'] = self.sapSysNr
            record['timestamp'] = datetime.now(timezone.utc)

    """
    call RFC ENQUEUE_READ and return all current existing queues.
    """

    def _rfcReadEnqueueLog(self, connection: Connection, logTag: str):
        rfcName = 'ENQUEUE_READ'
        self.tracer.info(("[%s] invoking rfc %s for hostname=%s for client %s"),
                         logTag,
                         rfcName,
                         self.sapHostName,
                         self.sapClient)

        try:
            lock_result = connection.call(rfcName,
                                          GUNAME="*")
            return lock_result
        except CommunicationError as e:
            self.tracer.error("[%s] communication error for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)

        except ABAPApplicationError as e:
            self.tracer.error("[%s] Exception raised for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)

        except ABAPRuntimeError as e:
            self.tracer.error("[%s] Runtime error for rfc %s with hostname: %s (%s). Update the roles in SAP System using role file %s",
                              logTag, rfcName, self.sapHostName, e, self.rolesFileURL, exc_info=True)

        except Exception as e:
            self.tracer.error("[%s] Error occured for rfc %s with hostname: %s (%s)",
                              logTag, rfcName, self.sapHostName, e, exc_info=True)

        return None

    """
    take parsed ENQUEUE_READ result set and decorate each record with additional fixed set of 
    properties needed for metrics records
    """

    def _decorateLockMetrics(self, records: list) -> None:
        currentTimestamp = datetime.now(timezone.utc)
        serverRegex = re.compile(
            r"(?P<hostname>.+?)_(?P<SID>[^_]+)_(?P<instanceNr>[0-9]+)")
        for record in records:
            # parse GTDATE/GTTIME fields into serverTimestamp
            record['serverTimestamp'] = self._datetimeFromDateAndTimeString(
                record['GTDATE'], record['GTTIME'])
            # value returned by SAP for S4HANA - 's4tsts4dci_S4D_00...............'
            # value returned by SAP for SQL - 'SAPTSTGTMCI..................'
            # code to give a consistent format to GTHOST for different values returned by SAP
            # and use the regex to decorate the table with hostname, SID and InstanceNr
            actual_hostname = record["GTHOST"].split(".")[0]
            if(actual_hostname.find(self.sapSid) > 0):
                record['GTHOST'] = actual_hostname
            else:
                record['GTHOST'] = actual_hostname + "_" + \
                    self.sapSid + "_" + record["GTSYSNR"]
            # parse SERVER field into hostname/SID/InstanceNr properties
            m = serverRegex.match(record['GTHOST'])
            if m:
                fields = m.groupdict()
                record['hostname'] = fields['hostname']
                record['SID'] = fields['SID']
                record['instanceNr'] = fields['instanceNr']
            else:
                self.tracer.error(
                    "[%s] record had unexpected SERVER format: %s", record['GTSYSNR'])
                record['hostname'] = ''
                record['SID'] = ''
                record['instanceNr'] = ''

            record['client'] = self.sapClient
            record['subdomain'] = self.sapSubdomain
            record['timestamp'] = currentTimestamp
