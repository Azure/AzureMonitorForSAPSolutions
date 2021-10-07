# Python modules
from abc import ABC, abstractmethod, abstractproperty
from datetime import date, datetime, timedelta, timezone
from time import time
import logging
from typing import Callable, Dict, List, Optional

# Payload modules
from helper.tools import *

# soap client cache expiration, after which amount of time both successful + failed soap client instantiation attempts will be refreshed
SOAP_CLIENT_CACHE_EXPIRATIION = timedelta(minutes=10)

##########
# Abstract base class to represent interface for querying Server/System time from SAP system
##########
class ServerTimeClientBase(ABC):

    def __init__(self, tracer: logging.Logger):
        self.tracer = tracer

    @abstractmethod
    def getServerTimestamp(self, logTag: str) -> datetime:
        pass

##########
# Abstract base class to represent interface for SAPStartSvc SOAP API metric extraction client implementation
##########

class NetWeaverSoapClientBase(ABC):

    def __init__(self, tracer: logging.Logger):
        self.tracer = tracer

    # the fully qualified WSDL url that was used to initialize this SOAP client
    @abstractproperty
    def Wsdl(self) -> str:
        pass

    # invoke GetSystemInstanceList SOAP API - returns list of metadata for all server instances in SAP system, including availability status and SAP instance features/functions
    # applies to all instances within SAP system
    @abstractmethod
    def getSystemInstanceList(self, logTag: str) -> list:
        pass

    # invoke GetProcessList SOAP API - metrics for availability of SAP services running on all machines in SAP system
    # applies to all instances within SAP system
    @abstractmethod
    def getProcessList(self, logTag: str) -> list:
        pass

    # invoke ABAPGetWPTable SOAP API - metrics for active ABAP worker processes
    # applies to hosts with features:  ABAP
    @abstractmethod
    def getAbapWorkerProcessTable(self, logTag: str) -> list:
        pass

    # invoke GetQueueStatistic SOAP API - metrics for application server worker process queues
    # applies to hosts with features:  ABAP, J2EE, JEE
    @abstractmethod
    def getQueueStatistic(self, logTag: str) -> list:
        pass

    # invoke EnqGetStatistic SOAP API - metrics from ENQUE server around enqueue lock statistics
    # applies to hosts with features:  ENQUE
    @abstractmethod
    def getEnqueueServerStatistic(self, logTag: str) -> list:
        pass

    # invoke GetEnvironment SOAP API - host details from SAP instance
    # used for mapping all hosts with azure resource id
    @abstractmethod
    def getEnvironment(self, logTag: str) -> list:
        pass

##########
# Abstract base class to represent interface for SAP NetWeaver SMON and SWNC Workload metric extraction client implementations
##########

class NetWeaverMetricClient(ABC):
    #__metaclass__ = ABCMeta

    def __init__(self,
                 tracer: logging.Logger):
        self.tracer = tracer

    @abstractproperty
    def Hostname(self) -> str:
        pass

    @abstractproperty
    def InstanceNr(self) -> str:
        pass

    # validate that config settings and that client can establish connection
    @abstractmethod
    def validate(self) -> bool:
        pass

    # determine appropriate query window start / end time range
    @abstractmethod
    def getQueryWindow(self,
                       lastRunTime: datetime,
                       minimumRunIntervalSecs: int,
                       serverTimeZone: timezone,
                       logTag: str) -> tuple:
        pass

    # query sap instance to get current server time
    @abstractmethod
    def getServerTime(self, logTag: str) -> datetime:
        pass

    # fetch all /SDF/SMON_ANALYSIS_READ metric data and return as a single json string
    @abstractmethod
    def getSmonMetrics(self, startDateTime: datetime, endDateTime: datetime, logTag: str) -> str:
        pass

    # fetch SWNC_GET_WORKLOAD_SNAPSHOT data, calculate aggregate metrics and return as json string
    @abstractmethod
    def getSwncWorkloadMetrics(self, startDateTime: datetime, endDateTime: datetime, logTag: str) -> str:
        pass

    # fetch GET_DUMP_LOG metrics and return as json string
    @abstractmethod
    def getShortDumpsMetrics(self, startDateTime: datetime, endDateTime: datetime, logTag: str) -> str:
        pass

    # fetch GET_SYS_LOG metrics and return as json string
    @abstractmethod
    def getSysLogMetrics(self, startDateTime: datetime, endDateTime: datetime, logTag: str) -> str:
        pass

    # fetch RFC_READ_TABLE metrics and return as json string
    @abstractmethod
    def getFailedUpdatesMetrics(self, logTag: str) -> str:
        pass

    # fetch  BAPI_XBP_JOB_SELECT metrics and return as json string
    @abstractmethod
    def getBatchJobMetrics(self, startDateTime: datetime, endDateTime: datetime, logTag: str) -> str:
        pass

    # fetch TRFC_QIN_GET_CURRENT_QUEUES metrics and return as json string
    @abstractmethod
    def getInboundQueuesMetrics(self, logTag: str) -> str:
        pass

    # fetch TRFC_QOUT_GET_CURRENT_QUEUES metrics and return as json string
    @abstractmethod
    def getOutboundQueuesMetrics(self, logTag: str) -> str:
        pass

    # fetch ENQUEUE_READ metrics and return as json string
    @abstractmethod
    def getEnqueueReadMetrics(self, logTag: str) -> str:
        pass

##########
# helper class to instantiate SAP NetWeaver Metric clients while only requiring clients to be aware of interface
##########


class MetricClientFactory:

    # static class variable to keep cache of all successfully initialized SOAP metric clients
    # using a lookup key of the WSDL url.
    _soapClientCache = {}

    @staticmethod
    def getMetricClient(tracer: logging.Logger,
                        logTag: str,
                        sapHostName: str,
                        sapSubdomain: str,
                        sapSysNr: str,
                        sapClient: str,
                        sapUsername: str,
                        sapPassword: str,
                        sapLogonGroup: str,
                        sapSid: str,
                        columnFilterList: List[str] = None,
                        serverTimeZone: str = None) -> NetWeaverMetricClient:
        try:
            import pyrfc
            from netweaver.rfcclient import NetWeaverRfcClient
            return NetWeaverRfcClient(tracer=tracer,
                                      sapHostName=sapHostName,
                                      sapSubdomain=sapSubdomain,
                                      sapSysNr=sapSysNr,
                                      sapClient=sapClient,
                                      sapUsername=sapUsername,
                                      sapPassword=sapPassword,
                                      sapLogonGroup=sapLogonGroup,
                                      sapSid=sapSid,
                                      columnFilterList=columnFilterList,
                                      serverTimeZone=serverTimeZone)
        except ImportError as importEx:
            tracer.error("[%s] failed to import pyrfc module, unable to initialize NetWeaverRfcClient: ",
                         logTag, importEx, exc_info=True)
            raise
        except Exception as ex:
            tracer.error(
                "[%s] Unexpected failure trying to create NetWeaverRfcClient: ", logTag, ex, exc_info=True)
            raise

    """
    attempt to initialize SOAP client for SAP hostname using default HTTPS port based on SAP InstanceNr (5XX14),
    and if that fails then attempt to initialize SOAP client on default HTTP port (5XX13),
    and only throw exception if both attempts fail
    """
    @staticmethod
    def getSoapMetricClientForSapInstance(tracer: logging.Logger,
                                          logTag: str,
                                          sapSid: str,
                                          sapHostName: str,
                                          sapSubdomain: str,
                                          sapInstanceNr: str,
                                          useCache: bool = True) -> NetWeaverSoapClientBase:
        from netweaver.soapclient import NetWeaverSoapClient

        fqdn = NetWeaverSoapClient._getFullyQualifiedDomainName(
            sapHostName, sapSubdomain)

        httpsPort = int(
            NetWeaverSoapClient._getHttpsPortFromInstanceNr(sapInstanceNr))
        httpPort = int(
            NetWeaverSoapClient._getHttpPortFromInstanceNr(sapInstanceNr))

        httpProtocolAndPorts = [(httpsPort, "https"), (httpPort, "http")]
        lastException = None
        startTime = time()
        for httpPort, httpProtocol in httpProtocolAndPorts:
            try:
                # try to create SOAP client for specific host + port + http Protocol,
                # and use a cached client instance if one already exists
                client = MetricClientFactory.getSoapMetricClientForHostAndPort(tracer=tracer,
                                                                               logTag=logTag,
                                                                               sapSid=sapSid,
                                                                               sapHostName=sapHostName,
                                                                               sapSubdomain=sapSubdomain,
                                                                               httpProtocol=httpProtocol,
                                                                               httpPort=httpPort,
                                                                               useCache=useCache)
                return client
            except Exception as ex:
                # save last exception in the event we fail to create client on all ports/protocols and we want to throw
                lastException = ex

        tracer.error("%s Failed to create NetWeaverSoapClient on default ports for host=%s, instanceNr=%s [%d ms]",
                     logTag, fqdn, sapInstanceNr, TimeUtils.getElapsedMilliseconds(startTime))
        raise lastException

    """
    attempt to initialize SOAP client for SAP hostname using a specific http protocol and port.
    This will involve fetching the SOAP WSDL from the remote host via http call, which is then used define
    the client APIs available.  If we have a previously cached attempt to initialize the a SOAP client
    for this WSDL, and it is within TTL, then go ahead and return the cached client 
    (if success, or throw exception if last attempt failed)
    The client cache significantly reduces the # of off-box calls we have to make, since fetching the WSDL 
    for ever API call would result in 2x the outgoing request load.
    """
    @staticmethod
    def getSoapMetricClientForHostAndPort(tracer: logging.Logger,
                                          logTag: str,
                                          sapSid: str,
                                          sapHostName: str,
                                          sapSubdomain: str,
                                          httpProtocol: str,
                                          httpPort: int,
                                          useCache: bool = True) -> NetWeaverSoapClientBase:
        from netweaver.soapclient import NetWeaverSoapClient

        wsdl = NetWeaverSoapClient._getFullyQualifiedWsdl(
            sapHostName, sapSubdomain, httpProtocol, httpPort)

        # see if we have SOAP client we can use for this specific hostname + port, since instantiating
        # a new SOAP client involves making off box call to fetch WSDL so we try to avoid doing that more often than needed
        if (useCache and wsdl in MetricClientFactory._soapClientCache):
            cacheEntry = MetricClientFactory._soapClientCache[wsdl]
            # only return cached SOAP client if the cache TTL has not expired
            if (cacheEntry['expirationDateTime'] > datetime.utcnow()):
                if (cacheEntry['client']):
                    # return cached SOAP client
                    return cacheEntry['client']
                else:
                    # cached soap client was not initialized successfully, so throw
                    raise Exception(
                        "%s cached NetWeaverSoapClient failure for wsdl: %s", logTag, wsdl)

        # no valid cached client was found, so try to fetch WSDL for this specific host and port
        startTime = time()
        client = None
        try:
            client = NetWeaverSoapClient(tracer=tracer,
                                         logTag=logTag,
                                         sapSid=sapSid,
                                         sapHostName=sapHostName,
                                         sapSubdomain=sapSubdomain,
                                         httpProtocol=httpProtocol,
                                         httpPort=httpPort)

            tracer.info("%s success initializing NetWeaverSoapClient for wsdl: %s [%d ms]",
                        logTag, wsdl, TimeUtils.getElapsedMilliseconds(startTime))
            return client
        except Exception as ex:
            tracer.error("%s error initializing NetWeaverSoapClient for wsdl: %s, [%d ms] %s",
                         logTag, wsdl, TimeUtils.getElapsedMilliseconds(startTime), ex, exc_info=True)
            raise
        finally:
            # cache soap client result, whether success or failure
            MetricClientFactory._soapClientCache[wsdl] = {
                'client': client,
                'expirationDateTime': datetime.utcnow() + SOAP_CLIENT_CACHE_EXPIRATIION
            }

    """
    factory method to create a SAP Server Time client based on Message Server HTTP client implementation
    NOTE:  no client object caching needed since instantiating the client is cheap, unlike the SOAP client
    """
    @staticmethod
    def getMessageServerClientForSapInstance(tracer: logging.Logger,
                                             logTag: str,
                                             sapSid: str,
                                             sapHostName: str,
                                             sapSubdomain: str,
                                             sapInstanceNr: str) -> ServerTimeClientBase:
        try:
            from netweaver.messageserverclient import MessageServerHttpClient

            return MessageServerHttpClient(tracer=tracer,
                                           logTag=logTag,
                                           sapSid=sapSid,
                                           sapHostName=sapHostName,
                                           sapSubdomain=sapSubdomain,
                                           sapInstanceNr=sapInstanceNr)
        except Exception as ex:
            tracer.error("%s Unexpected failure trying to create MessageServerHttpClient for host:%s, subdomain:%s, instance:%s, %s",
                         logTag,
                         sapHostName,
                         sapSubdomain,
                         sapInstanceNr,
                         ex,
                         exc_info=True)
            raise
