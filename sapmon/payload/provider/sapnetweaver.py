# Python modules
import json
import logging
from datetime import datetime, timedelta, timezone
from time import time
from typing import Any, Callable, Dict, List, Optional
import re
from threading import Lock
from pandas import merge, DataFrame

# Payload modules
from aiops.aiopshelper import *
from aiops.aiopshelperfactory import *
from const import *
from helper.azure import AzureStorageAccount
from helper.context import *
from helper.tools import *
from provider.base import ProviderInstance, ProviderCheck
from netweaver.metricclientfactory import NetWeaverMetricClient, NetWeaverSoapClientBase, ServerTimeClientBase, MetricClientFactory
from netweaver.rfcsdkinstaller import PATH_RFC_SDK_INSTALL, SapRfcSdkInstaller
from netweaver.soapclient import NetWeaverSoapClient
from netweaver.soapclientvalidator import SoapClientValidator
from typing import Dict

# Suppress SSLError warning due to missing SAP server certificate
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# wait time in between attempts to re-download and install RFC SDK package if we have a download blob
# URL defined and previous install attempt was not successful
MINIMUM_RFC_INSTALL_RETRY_INTERVAL = timedelta(minutes=30)

# SAPServerTimezone cache expiration time
SERVER_TIMEZONE_CACHE_EXPIRATIION = timedelta(seconds=60)

class sapNetweaverProviderInstance(ProviderInstance):
    # static / class variables to enforce singleton behavior around rfc sdk installation attempts across all 
    # instances of SAP Netweaver provider
    _isRfcInstalled = None
    _rfcInstallerLock = Lock()

    def __init__(self,
                tracer: logging.Logger,
                ctx: Context,
                providerInstance: Dict[str, str],
                skipContent: bool = False,
                **kwargs) -> None:
        self.sapSid = None
        self.sapHostName = None
        self.sapInstanceNr = None
        self.sapSubdomain = None

        # RFC SDK call settings
        self.sapUsername = None
        self.sapPassword = None
        self.sapClientId = None
        self.sapRfcSdkBlobUrl = None
        self.sapLogonGroup = None

        # provider instance flag for whether RFC calls should be enabled for this specific Netweaver provider instance
        self._areRfcCallsEnabled = None

        # cache WSDL SOAP clients so we can re-use them across checks for the same provider and cut down off-box calls
        self._soapClientCache = {}

        # cache timezone so we can re-use them until the cache expiration time in the same process
        self._timeZoneCache = {'timeZone':None}
        # the RFC SDK does not allow client to specify a timeout and in fact appears to have a connection timeout of 60 secs. 
        # In cases where RFC calls timeout due to some misconfiguration, multiple retries can lead to metric gaps of several minutes.  
        # We are limiting retries here because it is extremely rare for SOAP or RFC call to fail on first attempt and succeed on retry,
        # as most of these failures are due to persistent issues.  Better to not waste limited time budget.
        retrySettings = {
            "retries": 1,
            "delayInSeconds": 1,
            "backoffMultiplier": 2
        }

        super().__init__(tracer,
                       ctx,
                       providerInstance,
                       retrySettings,
                       skipContent,
                       **kwargs)

    """
    parse provider properties and get sid, host name and instance number
    """
    def parseProperties(self) -> bool:
        self.sapSid = self.metadata.get("sapSid", "")
        if not self.sapSid:
            self.tracer.error("%s sapSid cannot be empty", self.fullName)
            return False

        # provider level common logging prefix
        self.logTag = "[%s][%s]" % (self.fullName, self.sapSid)

        self.sapHostName = self.providerProperties.get("sapHostName", None)
        if not self.sapHostName:
            self.tracer.error("%s sapHostName cannot be empty", self.logTag)
            return False

        instanceNr = self.providerProperties.get("sapInstanceNr", None)
        if instanceNr is None: # 0 is an acceptable value for Instance Number
            self.tracer.error("%s sapInstanceNr cannot be empty", self.logTag)
            return False
        if not type(instanceNr) is int or instanceNr < 0 or instanceNr > 98:
            self.tracer.error("%s sapInstanceNr can only be between 00 and 98 but %s was passed", self.logTag, str(instanceNr))
            return False
        self.sapInstanceNr = str(instanceNr).zfill(2)
        self.sapSubdomain = self.providerProperties.get("sapSubdomain", "")

        self.sapUsername = self.providerProperties.get('sapUsername', None)
        self.sapPassword = self.providerProperties.get('sapPassword', None)
        self.sapClientId = self.providerProperties.get('sapClientId', None)
        self.sapLogonGroup = self.providerProperties.get('sapLogonGroup',None)
        self.sapRfcSdkBlobUrl = self.providerProperties.get('sapRfcSdkBlobUrl', None)

        # if user did not specify password directly via UI, check to see if they instead
        # provided link to Key Vault secret
        if not self.sapPassword:
            sapPasswordKeyVaultUrl = self.providerProperties.get("sapPasswordKeyVaultUrl", None)
            if sapPasswordKeyVaultUrl:
                self.tracer.info("%s sapPassword key vault URL specified, attempting to fetch from %s", self.logTag, sapPasswordKeyVaultUrl)

                try:
                    keyVaultUrlPatternMatch = re.match(REGEX_EXTERNAL_KEYVAULT_URL,
                                                       sapPasswordKeyVaultUrl,
                                                       re.IGNORECASE)
                    keyVaultName = keyVaultUrlPatternMatch.group(1)
                    secretName = keyVaultUrlPatternMatch.group(2)
                except Exception as e:
                    self.tracer.error("%s invalid sapPassword Key Vault secret url format: %s", self.logTag, sapPasswordKeyVaultUrl)
                    return False
                
                try:
                    kv = AzureKeyVault(self.tracer, keyVaultName, self.ctx.msiClientId)
                    self.sapPassword = kv.getSecret(secretName, None).value

                    if not self.sapPassword:
                        raise Exception("failed to read sapPassword secret")
                except Exception as e:
                    self.tracer.error("%s error fetching sapPassword secret from keyVault url: %s, %s",
                                      self.logTag, 
                                      sapPasswordKeyVaultUrl, 
                                      e)
                    return False

        return True

    """
    return a netweaver RFC client initialized with "MESSAGESERVER" instance we find
    for this SID.  
    """
    def getRfcClient(self, logTag: str) -> NetWeaverMetricClient:
        # RFC connections against application server instances can be made through 'MESSAGESERVER' instances
        dispatcherInstance = self.getMessageServerInstance()

        return MetricClientFactory.getMetricClient(tracer=self.tracer, 
                                                   logTag=logTag,
                                                   sapHostName=dispatcherInstance['hostname'],
                                                   sapSysNr=str(dispatcherInstance['instanceNr']),
                                                   sapSubdomain=self.sapSubdomain,
                                                   sapSid=self.sapSid,
                                                   sapClient=str(self.sapClientId),
                                                   sapLogonGroup = self.sapLogonGroup,
                                                   sapUsername=self.sapUsername,
                                                   sapPassword=self.sapPassword)

    def validate(self) -> bool:
        logTag = "[%s][%s][validation]" % (self.fullName, self.sapSid)

        # HACK: Load content json to fetch the list of APIs in the checks
        self.initContent()

        try:
            self._validateSoapClient()
        except Exception as e:
           self.tracer.error("%s SOAP API validation failure: %s", logTag, e, exc_info=True)
           return False
        try:
            self._validateRfcClient()
        except Exception as e:
            self.tracer.error("%s RFC client validation failure: %s", logTag, e, exc_info=True)
            return False

        return True

    """
    iterate through all SOAP API calls and attempt to validate that SOAP API client can be instantiated
    and expected APIs are callable
    """
    def _validateSoapClient(self) -> None:
        logTag = "[%s][%s][validation]" % (self.fullName, self.sapSid)

        self.tracer.info("%s validate SOAP API connectivity", logTag)

        validationErrors = []

        try:
            # first get list of SAP system instances
            apiName = 'GetSystemInstanceList'
            instances = self._validateGetSystemInstanceList(logTag="%s[%s]" % (logTag, apiName))

            apiName = 'GetProcessList'
            apiErrors = self._validateGetProcessList(logTag="%s[%s]" % (logTag, apiName), instances=instances)
            if (apiErrors.hasErrors):
                validationErrors.append("%s: %s" % (apiName, apiErrors.getValidationErrorsMessage()))

            apiName = 'ABAPGetWPTable'
            apiErrors = self._validateABAPGetWPTable(logTag="%s[%s]" % (logTag, apiName), instances=instances)
            if (apiErrors.hasErrors):
                validationErrors.append("%s: %s" % (apiName, apiErrors.getValidationErrorsMessage()))

            apiName = 'GetQueueStatistic'
            apiErrors = self._validateGetQueueStatistic(logTag="%s[%s]" % (logTag, apiName), instances=instances)
            if (apiErrors.hasErrors):
                validationErrors.append("%s: %s" % (apiName, apiErrors.getValidationErrorsMessage()))

            apiName = 'EnqGetStatistic'
            apiErrors = self._validateEnqGetStatistic(logTag="%s[%s]" % (logTag, apiName), instances=instances)
            if (apiErrors.hasErrors):
                validationErrors.append("%s: %s" % (apiName, apiErrors.getValidationErrorsMessage()))

            if (len(validationErrors) > 0):
                errorMsg = ', '.join(validationErrors)
                raise Exception("SOAP API validation errors: %s" % (errorMsg))

            self.tracer.info("%s SOAP client API validated successfully for SAP system", logTag)

        except Exception as e:
            self.tracer.error("%s error occurred while validating SOAP client API calls for SAP system: %s",
                              logTag,
                              e,
                              exc_info=True)
            raise

    def _validateGetSystemInstanceList(self, logTag: str) -> list:
        client = MetricClientFactory.getSoapMetricClientForSapInstance(tracer=self.tracer,
                                                                       logTag=logTag,
                                                                       sapSid=self.sapSid,
                                                                       sapHostName=self.sapHostName,
                                                                       sapSubdomain=self.sapSubdomain,
                                                                       sapInstanceNr=self.sapInstanceNr,
                                                                       useCache=False)
        
        return client.getSystemInstanceList(logTag=logTag)

    def _validateGetProcessList(self, logTag: str, instances: list) -> SoapClientValidator:
        # the filtered list of SAP instances that should support this SOAP API
        filteredInstances = self._getFilteredInstancesForSoapApiAction(instances, 
                                                                       checkName="GetProcessList", 
                                                                       apiName="GetProcessList")

        # SOAP client API to invoke
        clientFunc = lambda logTag, client: client.getProcessList(logTag=logTag)

        # invoke the SOAP API for all instanes and return aggregate errors summary
        return self._validateSoapApiForInstances(logTag=logTag, 
                                                 instances=filteredInstances, 
                                                 clientFunc=clientFunc)

    def _validateABAPGetWPTable(self, logTag: str, instances: list) -> SoapClientValidator:
        # the filtered list of SAP instances that should support this SOAP API
        filteredInstances = self._getFilteredInstancesForSoapApiAction(instances, 
                                                                       checkName="ABAPGetWPTable", 
                                                                       apiName="ABAPGetWPTable")

        # SOAP client API to invoke
        clientFunc = lambda logTag, client: client.getAbapWorkerProcessTable(logTag=logTag)

        # invoke the SOAP API for all instanes and return aggregate errors summary
        return self._validateSoapApiForInstances(logTag=logTag, 
                                                 instances=filteredInstances, 
                                                 clientFunc=clientFunc)
    
    def _validateGetQueueStatistic(self, logTag: str, instances: list) -> SoapClientValidator:
        # the filtered list of SAP instances that should support this SOAP API
        filteredInstances = self._getFilteredInstancesForSoapApiAction(instances, 
                                                                       checkName="GetQueueStatistic", 
                                                                       apiName="GetQueueStatistic")

        # SOAP client API to invoke
        clientFunc = lambda logTag, client: client.getQueueStatistic(logTag=logTag)

        # invoke the SOAP API for all instanes and return aggregate errors summary
        return self._validateSoapApiForInstances(logTag=logTag, 
                                                 instances=filteredInstances, 
                                                 clientFunc=clientFunc)

    def _validateEnqGetStatistic(self, logTag: str, instances: list) -> SoapClientValidator:
        # the filtered list of SAP instances that should support this SOAP API
        filteredInstances = self._getFilteredInstancesForSoapApiAction(instances, 
                                                                       checkName="EnqGetStatistic", 
                                                                       apiName="EnqGetStatistic")

        # SOAP client API to invoke
        clientFunc = lambda logTag, client: client.getEnqueueServerStatistic(logTag=logTag)

        # invoke the SOAP API for all instanes and return aggregate errors summary
        return self._validateSoapApiForInstances(logTag=logTag, 
                                                 instances=filteredInstances, 
                                                 clientFunc=clientFunc)

    """
    attempt to invoke specific SOAP client method against all SAP instances and return
    aggregate counts of all different error types encountered
    """
    def _validateSoapApiForInstances(self, 
                                     logTag: str, 
                                     instances: list, 
                                     clientFunc: Callable[[str, NetWeaverSoapClientBase], list]) -> SoapClientValidator:
        # intialize helper to categorize and aggregate SOAP client exceptions
        validationErrors = SoapClientValidator()

        for instance in instances:
            hostname = instance['hostname']
            instanceNr = instance['instanceNr']

            try:
                client = MetricClientFactory.getSoapMetricClientForSapInstance(tracer=self.tracer,
                                                                               logTag=logTag,
                                                                               sapSid=self.sapSid,
                                                                               sapHostName=hostname,
                                                                               sapSubdomain=self.sapSubdomain,
                                                                               sapInstanceNr=instanceNr,
                                                                               useCache=True)

                clientFunc(logTag, client)
            except Exception as e:
                 #  add this "{hostname}_{instanceNr}" and the exception to the validator for analysis and aggregation
                validationErrors.addException(hostname="%s_%s" % (hostname, instanceNr), ex=e)
            
        return validationErrors

    """
    return a filtered list of SAP instances that match the expected SAP features
    based on the provider check configuration properties
    """
    def _getFilteredInstancesForSoapApiAction(self, 
                                              instances: list, 
                                              checkName: str, 
                                              apiName: str) -> list:
        # parse provider config check properties (which come from JSON config file) to determine
        # which instance filter types (ie. include|exclude) and SAP feature names (ie. ABAP,ENQUE,etc...)
        # are supported by this SOAP API action
        parameters = self._getParametersForSoapApiAction(checkName=checkName, apiName=apiName)

        filterFeatures = parameters.get('filterFeatures', None)
        filterType = parameters.get('filterType', None)

        # now return filtered list of instances based the SAP feature that support this SOAP API
        return self.filterInstancesByFeature(instances, filterFeatures=filterFeatures, filterType=filterType)

    """
    iterate through provider check configurations and return the filtering parameters for the matching SOAP API
    check and the first matching API action name.  This is needed so we can validate SOAP API calls by 
    loading the same filter config parameters that are used when the metric collection action is executed as part of a monitor check
    {
        "name": "GetQueueStatistic",
        "description": "SAP Netweaver GetQueueStatistic",
        "customLog": "SapNetweaver_GetQueueStatistic",
        "frequencySecs": 60,
        "includeInCustomerAnalytics": true,
        "actions": [
            {
                "type": "ExecuteGenericWebServiceRequest",
                "parameters": {
                    "apiName": "GetQueueStatistic",
                    "filterFeatures": ["ABAP", "J2EE", "JEE"],
                    "filterType": "include"
                }
            }
        ]
    },
    """
    def _getParametersForSoapApiAction(self, checkName: str, apiName: str) -> dict:
        for check in self.checks:
            if (check.name != checkName):
                continue
            for action in check.actions:
                parameters = action.get("parameters", {})
                if (len(parameters) and parameters.get('apiName', '') == apiName):
                    # stop after we find the first API action with the expected name
                    return parameters

        # no matching parameters for for check + api, so
        return {}

    """
    if customer provided RFC SDK configuration, then validate that all required properties are specified
    and validate we can establish RFC client connections to APIs we need to call
    """
    def _validateRfcClient(self) -> None:
        logTag = "[%s][%s][validation]" % (self.fullName, self.sapSid)

        # skip install completely if no RFC config properties are populated
        if (not self.sapUsername and
            not self.sapPassword and
            not self.sapClientId and
            not self.sapLogonGroup and
            not self.sapRfcSdkBlobUrl):
            # customer has not chosen to enable RFC SDK, nothing to validate
            return

        # if any RFC properties were specified, then ensure all required RFC properties are populated
        if (not self.sapUsername or
            not self.sapPassword or
            not self.sapClientId or
            not self.sapLogonGroup or
            not self.sapRfcSdkBlobUrl):
            # customer specified only partial set of config properties needed to enable RFC, so fail validation
            raise Exception(
                "must specify all properties to enable RFC metric collection:  Username, Password, ClientId, LogonGroup and RfcSdkBlobUrl")

        if (not self.areRfcMetricsEnabled()):
            raise Exception("RFC SDK failed to install and is not usable")

        # initialize a client for the first healthy ABAP/Dispatcher instance we find
        client = self.getRfcClient(logTag=logTag)

        # update logging prefix with the specific instance details of the client
        sapHostnameStr = "%s|%s" % (client.Hostname, client.InstanceNr)

        # initialie timezone data for utc offset fetched from SAP server
        sapServerTimeZone = self.getRfcServerTimeZone()

        # get metric query window to lookback 10 minutes to see if any results are available.  If not that probably
        # indicates customer has not enabled SMON on their SAP system
        self.tracer.info(
            "%s attempting to fetch server timestamp from %s", logTag, sapHostnameStr)
        (startTime, endTime) = client.getQueryWindow(lastRunServerTime=None,
                                                     minimumRunIntervalSecs=600,
                                                     serverTimeZone=sapServerTimeZone,
                                                     logTag=logTag)

        # hard-coded list of available RFC methods that correspond to RFC metrics to validate
        # hashtable with method names as key and value as number of parameters in every method 
        # for example value=3 represents method that takes three parametres, and called conditionlly 
        rfcMethodwithParameterLength = {'getSmonMetrics':3,
                           'getSwncWorkloadMetrics':3,
                           'getShortDumpsMetrics':3,
                           'getSysLogMetrics':3,
                           'getFailedUpdatesMetrics':1,
                           'getBatchJobMetrics':3,
                           'getInboundQueuesMetrics':1,
                           'getOutboundQueuesMetrics':1,
                           'getEnqueueReadMetrics':2
        }
       
        self.tracer.info("%s connecting to sap to validate RFC metrics", logTag)

        for rfcMetricName in rfcMethodwithParameterLength:
            try:
                method = getattr(client, rfcMetricName)
                self.tracer.info(
                        "%s attempting to fetch %s metrics from %s", logTag, rfcMetricName, sapHostnameStr)
                # check for methods based on number of parameters
                if  rfcMethodwithParameterLength.get(rfcMetricName) == 1:
                    result = method(logTag=logTag)
                elif rfcMethodwithParameterLength.get(rfcMetricName) == 2: 
                    result = method(logTag=logTag, serverTimeZone=sapServerTimeZone )
                else:
                    result = method(startDateTime=startTime, endDateTime=endTime, logTag=logTag)
                self.tracer.info(
                        "%s successfully queried %s metrics from %s", logTag, rfcMetricName, sapHostnameStr)
            except Exception as e:
                self.tracer.error(
                    "[%s]-[%s] suppressing errors during validation of RFC method %s ", logTag, e, rfcMetricName, exc_info=True)
 
    """
    query SAP SOAP API to return list of all instances in the SID, but if caller specifies that cached results are okay
    and we have cached instance list with the provider instance, then just return the cached results
    """
    def getInstances(self, 
                     filterFeatures: list = None , 
                     filterType: str = None, 
                     useCache: bool = True) -> list:
        # Use cached list of instances if available since they should not change within a single monitor run;
        # but if cache is not available or if caller explicitly asks to skip cache then make the SOAP call
        if ('hostConfig' in self.state and 
            self.state['hostConfig'] and
            len(self.state['hostConfig']) > 0 and 
            useCache):
            # self.tracer.debug("%s using cached list of system instances", self.logTag)
            return self.filterInstancesByFeature(self.state['hostConfig'], filterFeatures=filterFeatures, filterType=filterType)

        self.tracer.info("%s getting list of system instances", self.logTag)
        startTime = time()

        instanceList = []
        hosts = self._getHosts()

        # Use last known hosts to fetch the updated list of hosts
        # Walk through the known hostnames and stop whenever any of them returns the list of all instances
        isSuccess = False
        for host in hosts:
            hostname, instanceNum, httpProtocol, port = host[0], host[1], host[2], host[3]

            try:
                # if we have a cached host config with already defined protocol and port, then we can initialize
                # client directly from that, otherwise we have to instantiate client using ports derived from the instance number
                # which will try the derived HTTPS port first and then fallback to derived HTTP port
                if (not httpProtocol or not port):
                    # client = self.getDefaultClient(hostname=hostname, instance=instanceNum)
                    # get SOAP client for the default port(s) based on the SAP instance number.
                    client = MetricClientFactory.getSoapMetricClientForSapInstance(tracer=self.tracer,
                                                                                   logTag=self.logTag,
                                                                                   sapSid=self.sapSid,
                                                                                   sapHostName=hostname,
                                                                                   sapSubdomain=self.sapSubdomain,
                                                                                   sapInstanceNr=instanceNum,
                                                                                   useCache=True)
                else:
                    # client = self.getClient(hostname, httpProtocol, port)
                    # get SOAP client for the specified hostname, HTTP protocol, and port
                    client = MetricClientFactory.getSoapMetricClientForHostAndPort(tracer=self.tracer,
                                                                                   logTag=self.logTag,
                                                                                   sapSid=self.sapSid,
                                                                                   sapHostName=hostname,
                                                                                   sapSubdomain=self.sapSubdomain,
                                                                                   httpProtocol=httpProtocol,
                                                                                   httpPort=port,
                                                                                   useCache=True)

                instanceList = client.getSystemInstanceList(logTag=self.logTag)

                # cache latest results in provider state
                self.state['hostConfig'] = instanceList

                isSuccess = True
                break
            except Exception as e:
                self.tracer.error("%s could not connect to SAP with hostname: %s and port: %s", self.logTag, hostname, port, exc_info=True)

        if not isSuccess:
            raise Exception("%s could not connect to any SAP instances with hosts %s [%d ms]" % \
                            (self.logTag, hosts, TimeUtils.getElapsedMilliseconds(startTime)))

        self.tracer.info("%s finished getting all system instances [%d ms]", self.logTag, TimeUtils.getElapsedMilliseconds(startTime))

        return self.filterInstancesByFeature(instanceList, filterFeatures=filterFeatures, filterType=filterType)

    """
    fetch cached instance list for this provider and filter down to the list 'ABAP' feature functions
    that are healthy (ie. have dispstatus attribute of 'SAPControl-GREEN').  Just return first in the list.
    """
    def getActiveDispatcherInstance(self):
        # Use cached list of instances if available since they don't change that frequently,
        # and filter down to only healthy dispatcher instances since RFC direct application server connection
        # only works against dispatchera
        dispatcherInstances = self.getInstances(filterFeatures=['ABAP'], filterType='include', useCache=True)
        healthyInstances = [instance for instance in dispatcherInstances if 'GREEN' in instance['dispstatus']]

        if (len(healthyInstances) == 0):
            raise Exception("No healthy ABAP/dispatcher instance found for %s" % self.sapSid)

        # return first healthy instance in list
        return healthyInstances[0]
    
    """
    fetch cached instance list for this provider and filter down to the list 'MESSAGESERVER' feature functions
    return the available message server
    """
    def getMessageServerInstance(self):
        # Use cached list of instances if available since they don't change that frequently,
        # and filter down to only healthy dispatcher instances since RFC direct application server connection
        # only works against dispatchera
        dispatcherInstances = self.getInstances(filterFeatures=['MESSAGESERVER'], filterType='include', useCache=True)
        
        if (len(dispatcherInstances) == 0):
            raise Exception("No MESSAGESERVER instance found for %s" % self.sapSid)
        
        # return first healthy instance in list
        return dispatcherInstances[0]
    
    """
    given a list of sap instances and a set of instance features (ie. functions) to include or exclude,
    apply filtering logic and return only those instances that match the filter conditions:
        'include' filter type will include any instance that matches any of the feature filters
        'exclude' filter type will exclude any instance that matches any of the feature filters
    """
    def filterInstancesByFeature(self, 
                                 sapInstances: list, 
                                 filterFeatures: list = None, 
                                 filterType: str = None) -> list:
        if not sapInstances:
            return []

        if (not filterFeatures or len(filterFeatures) == 0):
            return sapInstances
    
        self.tracer.info("%s filtering list of system instances based on features: %s", self.logTag, filterFeatures)

        instances = [(instance, instance['features'].split('|')) for instance in sapInstances]
       
        if filterType == "include":
            # Inclusion filter
            # Only include instances that match at least one of the filter features
            filtered_instances = [instance for (instance, instance_features) in instances \
                if not set(filterFeatures).isdisjoint(set(instance_features))]
        elif filterType == "exclude":
            # Exclusion filter
            # Only include instance that match none of the filter features
            filtered_instances = [instance for (instance, instance_features) in instances \
                if set(filterFeatures).isdisjoint(set(instance_features))]
        else:
            raise Exception("%s filterType '%s' is not supported filter type" % (self.logTag, filterType))

        return filtered_instances

    """
    query SAP system to return the current system timestamp approximation
    NOTE: this can be done different ways, for example by RFC calls, but since RFC calls are optional
    in the current design we do this instead by making simple HTTP request to the Message Server instance
    which will echo back the current server time using HTTP Response header named 'date'
    """
    def getServerTimestamp(self, logTag: str) -> datetime:
        try:
            messageServerInstance = self.getMessageServerInstance()
            hostname = messageServerInstance['hostname']
            instanceNr = messageServerInstance['instanceNr']

            client = MetricClientFactory.getMessageServerClientForSapInstance(tracer=self.tracer,
                                                                              logTag=logTag, 
                                                                              sapSid=self.sapSid,
                                                                              sapHostName=hostname,
                                                                              sapSubdomain=self.sapSubdomain,
                                                                              sapInstanceNr=instanceNr)

            return client.getServerTimestamp(logTag=logTag)
        except Exception as e:
            self.tracer.error("%s exception trying to fetch message server time: %s", logTag, e, exc_info=True)

        # if for some reason we fail to call the message server, then we default to collector VM time
        return datetime.utcnow()

    """
    private method to return default provider hostname config (what customer provided at time netweaver provided was added)
    or a fully fleshed out list of <hostname / instance # / https:Port> tuples based on a previous cached call to getInstances()
    """
    def _getHosts(self) -> list:
        # Fetch last known list from storage. If storage does not have list, use provided
        # hostname and instanceNr
        if ('hostConfig' not in self.state or 
            not self.state['hostConfig'] or 
            len(self.state['hostConfig']) == 0):
            self.tracer.info("%s no host config persisted yet, using user-provided host name and instance nr", self.logTag)
            hosts = [(self.sapHostName,
                      self.sapInstanceNr,
                      None,
                      None)]
        else:
            self.tracer.info("%s fetching last known host config", self.logTag)
            currentHostConfig = self.state['hostConfig']
            hosts = [(hostConfig['hostname'], 
                      hostConfig['instanceNr'], 
                      "https" if (hostConfig['httpsPort'] and hostConfig['httpsPort'] != "0") else "http", 
                      hostConfig['httpsPort'] if (hostConfig['httpsPort'] and hostConfig['httpsPort'] != "0") else hostConfig['httpPort']) for hostConfig in currentHostConfig]

        return hosts

    """
    returns flag to indicate whether provider checks should attempt to use RFC SDK client calls to fetch certain metrics.
    First time may perform fairly expensive checks to validate if RFC SDK is installed anc configured, and may attempt
    to download user provided blob to install to local system.  We only want to attempt this at most once per process,
    so first caller to this function will pay that cost and the resulting success/failure flag will be cached.
    """
    def areRfcMetricsEnabled(self) -> bool:
        if self._areRfcCallsEnabled != None:
            # the flag for whether RFC is usable has already been initialzed, so return 
            return self._areRfcCallsEnabled

        # there may be 1..N sapNetWeaverProviderInstance instances per sapmon process, and each instance
        # may choose to enable/disable RFC calls individually, but we should only attempt to install the 
        # RFC SDK at most once per process.  Use a static/class variable to determine if installation 
        # attempt has already been attempted and was success/failure, and do all this inside of 
        # a lock and cache flag for future checks
        try:
            # class singleton lock
            sapNetweaverProviderInstance._rfcInstallerLock.acquire(blocking=True)

            # check -> lock -> check
            if (self._areRfcCallsEnabled != None):
                # flag was initialized prior to obtaining the lock
                return self._areRfcCallsEnabled

            # ensure this provider instance has necessary config settings to enable RFC SDK calls
            if (not self.sapUsername or
                not self.sapPassword or
                not self.sapClientId or
                not self.sapRfcSdkBlobUrl or
                not self.sapLogonGroup):
                self.tracer.info("%s Netweaver RFC calls disabled for because missing one or more required " +
                                 "config properties: sapUsername, sapPassword, sapClientId, sapLogonGroup and sapRfcSdkBlobUrl",
                                 self.logTag)
                self._areRfcCallsEnabled = False
                return False

            # only attempt to install RFC SDK once per process execution
            if (sapNetweaverProviderInstance._isRfcInstalled == None):
                sapNetweaverProviderInstance._isRfcInstalled = self._trySetupRfcSdk()
                
            self._areRfcCallsEnabled = sapNetweaverProviderInstance._isRfcInstalled

            return self._areRfcCallsEnabled

        except Exception as e:
            self.tracer.error("%s Exception trying to check if rfc sdk metrics are enabled, %s", self.logTag, e, exc_info=True)
            sapNetweaverProviderInstance._isRfcInstalled = False
            self._areRfcCallsEnabled = False

        finally:
            sapNetweaverProviderInstance._rfcInstallerLock.release()

        return False
    
    """
    validate that RFC SDK package has been installed and configured correctly and is usable by pyrfc module.
    If pyrfc module cannot be imported, then potentially attempt to download RFC SDK blob, install to local system,
    and configure necessary environment variables and system settings so that the libraries can be
    successfully loaded by the pyrfc module.  
    Returns flag indicating whether pyrfc module can be imnported (ie. whether RFC calls can be enabled)

    Pre-requisites for RFC SDK installation attempt:
    1.) Customer provided config property sapRfcSdkBlobUrl must be non-empty.
    2.) python module for "pynwrfc" must be installed
    3.) was the last failed SDK installation attempt more than N minutes ago (defined by MINIMUM_RFC_INSTALL_RETRY_INTERVAL)
    4.) does the sapRfcSdkBlobUrl provided by customer actually exist in the storage account
    5.) was the last_modified timestamp on the sapRfcSdkBlobUrl blob modified since the last failed installation attempt
    """
    def _trySetupRfcSdk(self) -> bool:
        try:
            # if no RFC SDK download blob url specified, treat as kill switch to disable any RFC calls
            if (not self.sapRfcSdkBlobUrl):
                self.tracer.info("%s No user provided RFC SDK blob url, will not leverage RFC SDK. quitting...", self.logTag)
                return False

            installer = SapRfcSdkInstaller(tracer=self.tracer, installPath=PATH_RFC_SDK_INSTALL)

            # environment variables must be initialized before RFC and pyrfc installation can be validated
            self.tracer.info("%s initializing RFC SDK environment...", self.logTag)
            if (not installer.initRfcSdkEnvironment()):
                self.tracer.error("%s failed to initialize rfc sdk environment pre-requisites", self.logTag)
                return False

            # if we are able to successfully import the pyrfc connector module, that means RFC SDK
            # libraries must be installed and were able to be found by pyrfc package initialization,
            # so no need to do any further checks.
            if (installer.isPyrfcModuleUsable()):
                # pyrfc package is usable, which means RFC SDK is already installed and environment configured correctly
                self.tracer.info("%s Pyrfc module is usable, RFC calls will be enabled", self.logTag)
                return True

            # if pyrfc module cannot be imported, check to see if it is even installed.  Assumption is that
            # pyrfc module is installed as part of container image, so if it is missing something is wrong
            # there is no need to even try to install the RFC SDK
            if (not installer.isPyrfcModuleInstalled()):
                self.tracer.error("%s Pyrfc module is not installed, RFC calls will be disabled", self.logTag)
                return False

            # check last sdk install attempt time so we can limit how often we retry
            # to download and install SDK on persistent failures (eg. no more than once every 30 mins)
            lastSdkInstallAttemptTime = installer.getLastSdkInstallAttemptTime()
            if (lastSdkInstallAttemptTime > (datetime.now(timezone.utc) - MINIMUM_RFC_INSTALL_RETRY_INTERVAL)):
                self.tracer.info("%s last RFC SDK install attempt was %s, minimum attempt retry %s, skipping...",
                                 self.logTag,
                                 lastSdkInstallAttemptTime, 
                                 MINIMUM_RFC_INSTALL_RETRY_INTERVAL)
                return False

            self.tracer.info("%s RFC SDK is not installed, so attempt installation now...", self.logTag)
            blobStorageAccount = AzureStorageAccount(tracer=self.tracer,
                                                     sapmonId=self.ctx.sapmonId,
                                                     msiClientId=self.ctx.msiClientId,
                                                     subscriptionId=self.ctx.vmInstance["subscriptionId"],
                                                     resourceGroup=self.ctx.vmInstance["resourceGroupName"])
    
            # first check that rfc sdk download blob exists in Azure Storage account, and if it 
            # exixts also fetch the last_modified timestamp metadata
            doesPackageExist, packageLastModifiedTime = installer.isRfcSdkAvailableForDownload(
                blobUrl=self.sapRfcSdkBlobUrl, 
                storageAccount=blobStorageAccount)

            if (not doesPackageExist):
                self.tracer.error("%s User provided RFC SDK blob does not exist %s, skipping...", self.logTag, self.sapRfcSdkBlobUrl)
                return False
            
            self.tracer.info("%s user provided RFC SDK blob exists for download %s, lastModified=%s",
                             self.logTag, self.sapRfcSdkBlobUrl, packageLastModifiedTime)
            
            # the user provided sdk blob exists, so before we download compare the last_modified timestamp
            # with the last modified time of the last download attempt.  If nothing has changed, 
            # then no need to try and download the package again
            # TODO:  confirm, should we go ahead and try to re-download previously failed packages
            #        once every 30 minutes anyway?  just in case failure was something external?
            lastInstallPackageModifiedTime = installer.getLastSdkInstallPackageModifiedTime()

            if (packageLastModifiedTime == lastInstallPackageModifiedTime):
                self.tracer.info("%s rfc sdk download package has not been modified since last download " +
                                 "attempt (last_modified=%s), will not download again",
                                 self.logTag, 
                                 lastInstallPackageModifiedTime)
                return False
            
            self.tracer.info("%s user provided rfc sdk package last_modified (%s) has changed " + 
                             "since last install attempt (%s), attempting to re-download and install",
                             self.logTag,
                             packageLastModifiedTime,
                             lastInstallPackageModifiedTime)

            # try to download user provided RFC SDK blob, install to local system and configure necessary
            # environment variables and system settings so that it can be usable by pyrfc module
            if (not installer.downloadAndInstallRfcSdk(blobUrl=self.sapRfcSdkBlobUrl, storageAccount=blobStorageAccount)):
                self.tracer.error("%s failed to download and install rfc sdk package, RFC calls will not be enabled...", self.logTag)
                return False

            # on Linux pyrfc module may not be usable upon first install attempt, as it appears that unpacking
            # libraries to the LD_LIBRARY_PATH env variable after the python process starts may not pick up the change.
            # The module should be usable on the next sapmon process run.
            if (not installer.isPyrfcModuleUsable()):
                self.tracer.error("%s pyrfc module still not usable after RFC SDK install (might require process restart), " + 
                                  "RFC calls will not be enabled...", 
                                  self.logTag)
                return False

            self.tracer.info("%s pyrfc module is usable after RFC SDK install, RFC calls will be enabled...", self.logTag)
            return True

        except Exception as e:
            self.tracer.error("%s exception trying to setup and validate RFC SDK, RFC calls will be disabled: %s", self.logTag, e, exc_info=True)

        return False
    """
    cache timezone  value returned by RFC timezone function call and apply expiration datetime to avoid 
    multiple RFC function calls 
    
    """

    def getRfcServerTimeZone(self):
        logTag = "[%s][%s][ServerTimeZone]" % (self.fullName, self.sapSid)
        # check if cache dictionary has values initialized and  return the timezone
        if(self._timeZoneCache['timeZone'] != None and self._timeZoneCache['expirationDateTime'] > datetime.utcnow()):
            self.tracer.info("%s Return cached server timezone: ",
                               self._timeZoneCache['expirationDateTime'])
            return (self._timeZoneCache['timeZone'])
        else:
            # initialize timezone variables and cache expiration in a dictionary
            client = self.getRfcClient(logTag=logTag)
            sapServerTimeZone = client.getLocalTimeZone(logTag=logTag)
            if sapServerTimeZone != None:
                    self._timeZoneCache['timeZone'] = sapServerTimeZone['ES_TTZZ']
                    self._timeZoneCache['expirationDateTime'] = datetime.utcnow(
                    ) + SERVER_TIMEZONE_CACHE_EXPIRATIION
                    self.tracer.info("%s Caching Server timezone at: ",
                                     self._timeZoneCache['expirationDateTime'])
            else:
                    self._timeZoneCache['timeZone'] = None
        return self._timeZoneCache['timeZone']

###########################
class sapNetweaverProviderCheck(ProviderCheck):
    lastResult = []

    # hard-coded set of action names that require RFC SDK to be usable 
    # and can override runtime isEnabled() check if RFC is not usable
    rfcCheckNames = {'SMON_Metrics', 'SWNC_Workload_Metrics', 'SDF_Short_Dumps_Metrics', 'Sys_Log_Metrics', 
                     'Failed_Updates_Metrics', 'Batch_Jobs_Metrics', 'Inbound_Queues_Metrics', 'Outbound_Queues_Metrics', 
                     'Enqueue_Read_Metrics'}

    aiopsCheckNames = {"SAP_Host_AzRId_Mapping"}

    def __init__(self,
        provider: ProviderInstance,
        **kwargs
    ):
        super().__init__(provider, **kwargs)
        self.lastRunLocal = None
        self.lastRunServer = None

        # provider check common logging prefix
        self.logTag = "[%s][%s]" % (self.fullName, self.providerInstance.sapSid)

    """
    return flag indicating whether this check instances requires the SAP RFC SDK to be installed and usable
    """
    def doesCheckRequireRfcSdk(self) -> bool:
        return self.name in sapNetweaverProviderCheck.rfcCheckNames

    """
    return flag indicating whether this check instance requires AIOPS to be enabled
    """
    def doesCheckRequireAIOps(self) -> bool:
        return self.name in sapNetweaverProviderCheck.aiopsCheckNames

    """
    override base ProviderCheck implementation to allow RFC metric collection methods enabled in
    the default Provider JSON configuration yet treated as disabled at runtime if RFC SDK
    is not configured (to reduce log spam)
    """
    def isEnabled(self) -> bool:
        if not self.state["isEnabled"]:
            return False
        
        # if this check requires RFC and RFC is not installed, then treat as disabled
        if (self.doesCheckRequireRfcSdk()):
            if (not self.providerInstance.areRfcMetricsEnabled()):
                return False

        if (self.doesCheckRequireAIOps()):
            if(not AIOpsHelper.isAIOpsEnabled(self.providerInstance.ctx)):
                return False
        
        return True
    
    ##############################
    # provider check action methods (to retrieve metrics and logs)
    ##############################

    """
    netweaver provider check action to query the SAP Control SOAP API to fetch snapshot
    of metadata and availability for all instances in SAP system
    """
    def _actionGetSystemInstanceList(self) -> None:
        self.tracer.info("%s refreshing list of system instances", self.logTag)
        self.lastRunLocal = datetime.utcnow()
        self.lastRunServer = self.providerInstance.getServerTimestamp(logTag=self.logTag)

        # when performing the actual provider check action, always fetch fresh instance list snapshot 
        # so that we can refresh the cache
        instanceList = self.providerInstance.getInstances(useCache=False)

        # Update host config, if new list is fetched
        # Parse dictionary and add current timestamp and SID to data and log it
        if len(instanceList) != 0:
            currentTimestamp = self._getFormattedTimestamp()
            for instance in instanceList:
                instance['timestamp'] = currentTimestamp
                instance['serverTimestamp'] = self.lastRunServer.isoformat()
                instance['SID'] = self.providerInstance.sapSid
                instance['subdomain'] = self.providerInstance.sapSubdomain

        self.lastResult = instanceList

        # Update internal state
        if not self.updateState():
            raise Exception("%s failed to update state" % self.logTag)

        self.tracer.info("%s successfully fetched system instance list", self.logTag)

    """
    netweaver provider check action to query the SAP Control SOAP API to fetch process list metadata 
    from all SAP application server instances
    """
    def _actionGetProcessList(self, apiName: str, filterFeatures: list, filterType: str) -> None:
        # define the SOAP API client function to invoke
        clientFunc = lambda logTag, client: client.getProcessList(logTag=logTag)
        # define function to remove sensitive data from SOAP API raw results
        sanitizeResultsFunc = lambda results: self._sanitizeGetProcessList(results)

        self._executeSoapApiForInstances(logTag=self.logTag, 
                                         apiName=apiName, 
                                         filterFeatures=filterFeatures, 
                                         filterType=filterType,
                                         clientFunc=clientFunc,
                                         sanitizeResultsFunc=sanitizeResultsFunc)

    """
    netweaver provider check action to query the SAP Control SOAP API to fetch computerNames for all sap instances 
    and map them with azure resource id (armId), fetched from Azure Resource Graph REST API
    """
    def _actionGetSapHostAzRIdMapping(self, apiName: str, filterFeatures: list, filterType: str) -> None:
        self.tracer.info("%s Running check SAP_Host_AzRId_Mapping", self.logTag)
        
        # define the SOAP API client function to invoke
        clientFunc = lambda logTag, client: client.getEnvironment(logTag=logTag)
        
        # define function to extract relevant data from SOAP API raw results
        sanitizeResultsFunc = lambda results: self._sanitizeGetEnvironmentDetails(results)
        
        startTime = time()
        self._executeSoapApiForInstances(logTag=self.logTag, 
                                        apiName=apiName, 
                                        filterFeatures=filterFeatures, 
                                        filterType=filterType,
                                        clientFunc=clientFunc,
                                        sanitizeResultsFunc=sanitizeResultsFunc)
        self.tracer.info("%s Total time to execute %s SOAP API calls = [%d ms]", 
                     self.logTag, apiName, TimeUtils.getElapsedMilliseconds(startTime))

        if(len(self.lastResult) > 0):
            startTime = time()
            self.lastResult = self._postProcessGetEnvironmentResults(self.lastResult)
            self.tracer.info("%s Time to perform post processing after %s SOAP API calls = [%d ms]", 
                     self.logTag, apiName, TimeUtils.getElapsedMilliseconds(startTime))

    """
    netweaver provider check action to query the SAP Control SOAP API to fetch worker process queue metrics
    for all SAP application server instances that support ABAP function
    """
    def _actionGetQueueStatistic(self, apiName: str, filterFeatures: list, filterType: str) -> None:
        # define the SOAP API client function to invoke
        clientFunc = lambda logTag, client: client.getQueueStatistic(logTag=logTag)

        self._executeSoapApiForInstances(logTag=self.logTag, 
                                         apiName=apiName, 
                                         filterFeatures=filterFeatures, 
                                         filterType=filterType,
                                         clientFunc=clientFunc,
                                         sanitizeResultsFunc=None)

    """
    netweaver provider check action to query the SAP Control SOAP API to fetch ABAP worker process metrics
    for all SAP application server instances that support ABAP function
    """
    def _actionABAPGetWPTable(self, apiName: str, filterFeatures: list, filterType: str) -> None:
        # define the SOAP API client function to invoke
        clientFunc = lambda logTag, client: client.getAbapWorkerProcessTable(logTag=logTag)

        # define function to remove sensitive data from SOAP API raw results
        sanitizeResultsFunc = lambda results: self._sanitizeABAPGetWPTable(results)

        self._executeSoapApiForInstances(logTag=self.logTag, 
                                         apiName=apiName, 
                                         filterFeatures=filterFeatures, 
                                         filterType=filterType,
                                         clientFunc=clientFunc,
                                         sanitizeResultsFunc=sanitizeResultsFunc)                                         

    """
    netweaver provider check action to query the SAP Control SOAP API to fetch Enqueue server lock statistics
    for the SAP application server instance that supports the ENQUE function
    """
    def _actionEnqGetStatistic(self, apiName: str, filterFeatures: list, filterType: str) -> None:
        # define the SOAP API client function to invoke
        clientFunc = lambda logTag, client: client.getEnqueueServerStatistic(logTag=logTag)

        self._executeSoapApiForInstances(logTag=self.logTag, 
                                         apiName=apiName, 
                                         filterFeatures=filterFeatures, 
                                         filterType=filterType,
                                         clientFunc=clientFunc,
                                         sanitizeResultsFunc=None)

    """
    netweaver provider check action to query for SDF/SMON Analysis Run metrics
    """
    def _actionGetSmonAnalysisMetrics(self) -> None:
        # base class will always call generateJsonString(), so we must always be sure to set the lastResult
        # regardless of success or failure
        self.lastResult = []

        try:
            # initialize hostname log string here to default of SID in case we cannot identify a specific dispatcher host
            sapHostnameStr = self.providerInstance.sapSid

            if (not self.providerInstance.areRfcMetricsEnabled()):
                self.tracer.info("%s Skipping SMON metrics because RFC SDK metrics not enabled...", self.logTag)
                return

            # track latency of entire method excecution with dependencies
            latencyStartTime = time()
            
            # initialize a client for the first healthy MessageServer instance we find
            client = self.providerInstance.getRfcClient(logTag=self.logTag)

            # update logging prefix with the specific instance details of the client
            sapHostnameStr = "%s|%s" % (client.Hostname, client.InstanceNr)
            
            # initialie timezone data for utc offset fetched from SAP server
            sapServerTimeZone = self.providerInstance.getRfcServerTimeZone()

            # get metric query window based on our last successful query where results were returned
            (startTime, endTime) = client.getQueryWindow(lastRunServerTime=self.lastRunServer,
                                                         minimumRunIntervalSecs=self.frequencySecs,
                                                         serverTimeZone=sapServerTimeZone,
                                                         logTag=self.logTag)
                                                         
            self.lastResult = client.getSmonMetrics(startDateTime=startTime, endDateTime=endTime, logTag=self.logTag)

            self.tracer.info("%s successfully queried SMON metrics for %s [%d ms]", 
                             self.logTag, sapHostnameStr, TimeUtils.getElapsedMilliseconds(latencyStartTime))
            self.lastRunLocal = datetime.now(timezone.utc)
            self.lastRunServer = endTime

            # only update state on successful query attempt
            self.updateState()

        except Exception as e:
            self.tracer.error("%s exception trying to fetch SMON Analysis Run metrics for %s [%d ms], error: %s", 
                              self.logTag,
                              sapHostnameStr,
                              TimeUtils.getElapsedMilliseconds(latencyStartTime),
                              e,
                              exc_info=True)
            raise
    
    """
    netweaver provider check action to query for SWNC workload statistics and decorate with ST03 metric calculations
    """
    def _actionGetSwncWorkloadMetrics(self) -> None:
        # base class will always call generateJsonString(), so we must always be sure to set the lastResult
        # regardless of success or failure
        self.lastResult = []

        try:
            # initialize hostname log string here to default of SID in case we cannot identify a specific dispatcher host
            sapHostnameStr = self.providerInstance.sapSid

            if (not self.providerInstance.areRfcMetricsEnabled()):
                self.tracer.info("%s Skipping SWNC metrics because RFC SDK metrics not enabled...", self.logTag)
                return

            # track latency of entire method excecution with dependencies
            latencyStartTime = time()

            # initialize a client for the first healthy MessageServer instance we find
            client = self.providerInstance.getRfcClient(logTag=self.logTag)

            # update logging prefix with the specific instance details of the client
            sapHostnameStr = "%s|%s" % (client.Hostname, client.InstanceNr)
            
            # initialie timezone data for utc offset fetched from SAP server
            sapServerTimeZone = self.providerInstance.getRfcServerTimeZone()

            # get metric query window based on our last successful query where results were returned
            (startTime, endTime) = client.getQueryWindow(lastRunServerTime=self.lastRunServer,
                                                         minimumRunIntervalSecs=self.frequencySecs,
                                                         serverTimeZone=sapServerTimeZone,
                                                         logTag=self.logTag)

            self.lastResult = client.getSwncWorkloadMetrics(startDateTime=startTime, endDateTime=endTime, logTag=self.logTag)

            self.tracer.info("%s successfully queried SWNC workload metrics for %s [%d ms]", 
                             self.logTag, sapHostnameStr, TimeUtils.getElapsedMilliseconds(latencyStartTime))
            self.lastRunLocal = datetime.now(timezone.utc)
            self.lastRunServer = endTime

            # only update state on successful query attempt
            self.updateState()

        except Exception as e:
            self.tracer.error("%s exception trying to fetch SWNC workload metrics for %s [%d ms], error: %s",
                              self.logTag,
                              sapHostnameStr,
                              TimeUtils.getElapsedMilliseconds(latencyStartTime),
                              e,
                              exc_info=True)
            raise
    
    """
    netweaver provider check action to query for short dumps
    """
    def _actionGetShortDumpsMetrics(self) -> None:
        # base class will always call generateJsonString(), so we must always be sure to set the lastResult
        # regardless of success or failure
        self.lastResult = []

        try:
            # initialize hostname log string here to default of SID in case we cannot identify a specific dispatcher host
            sapHostnameStr = self.providerInstance.sapSid

            if (not self.providerInstance.areRfcMetricsEnabled()):
                self.tracer.info("%s Skipping short dumps metrics because RFC SDK metrics not enabled...", self.logTag)
                return

            # track latency of entire method excecution with dependencies
            latencyStartTime = time()

            # initialize a client for the first healthy MessageServer instance we find
            client = self.providerInstance.getRfcClient(logTag=self.logTag)

            # update logging prefix with the specific instance details of the client
            sapHostnameStr = "%s|%s" % (client.Hostname, client.InstanceNr)
            
            # initialie timezone data for utc offset fetched from SAP server
            sapServerTimeZone = self.providerInstance.getRfcServerTimeZone()

            # get metric query window based on our last successful query where results were returned
            (startTime, endTime) = client.getQueryWindow(lastRunServerTime=self.lastRunServer,
                                                         minimumRunIntervalSecs=self.frequencySecs,
                                                         serverTimeZone=sapServerTimeZone,
                                                         logTag=self.logTag)

            self.lastResult = client.getShortDumpsMetrics(startDateTime=startTime, endDateTime=endTime, logTag=self.logTag)

            self.tracer.info("%s successfully queried short dumps metrics for %s [%d ms]", 
                             self.logTag, sapHostnameStr, TimeUtils.getElapsedMilliseconds(latencyStartTime))
            self.lastRunLocal = datetime.now(timezone.utc)
            self.lastRunServer = endTime

            # only update state on successful query attempt
            self.updateState()

        except Exception as e:
            self.tracer.error("%s exception trying to fetch short dumps metrics for %s [%d ms], error: %s",
                              self.logTag,
                              sapHostnameStr,
                              TimeUtils.getElapsedMilliseconds(latencyStartTime),
                              e,
                              exc_info=True)
            raise

    """
    netweaver provider check action to query for sys logs
    """
    def _actionGetSysLogMetrics(self) -> None:
        # base class will always call generateJsonString(), so we must always be sure to set the lastResult
        # regardless of success or failure
        self.lastResult = []

        try:
            # initialize hostname log string here to default of SID in case we cannot identify a specific dispatcher host
            sapHostnameStr = self.providerInstance.sapSid

            if (not self.providerInstance.areRfcMetricsEnabled()):
                self.tracer.info("%s Skipping sys logs metrics because RFC SDK metrics not enabled...", self.logTag)
                return

            # track latency of entire method excecution with dependencies
            latencyStartTime = time()

            # initialize a client for the first healthy MessageServer instance we find
            client = self.providerInstance.getRfcClient(logTag=self.logTag)

            # update logging prefix with the specific instance details of the client
            sapHostnameStr = "%s|%s" % (client.Hostname, client.InstanceNr)
            
            # initialie timezone data for utc offset fetched from SAP server
            sapServerTimeZone = self.providerInstance.getRfcServerTimeZone()

            # get metric query window based on our last successful query where results were returned
            (startTime, endTime) = client.getQueryWindow(lastRunServerTime=self.lastRunServer,
                                                         minimumRunIntervalSecs=self.frequencySecs,
                                                         serverTimeZone=sapServerTimeZone,
                                                         logTag=self.logTag)

            self.lastResult = client.getSysLogMetrics(startDateTime=startTime, endDateTime=endTime, logTag=self.logTag)

            self.tracer.info("%s successfully queried sys log metrics for %s [%d ms]", 
                             self.logTag, sapHostnameStr, TimeUtils.getElapsedMilliseconds(latencyStartTime))
            self.lastRunLocal = datetime.now(timezone.utc)
            self.lastRunServer = endTime

            # only update state on successful query attempt
            self.updateState()

        except Exception as e:
            self.tracer.error("%s exception trying to fetch sys logs metrics for %s [%d ms], error: %s",
                              self.logTag,
                              sapHostnameStr,
                              TimeUtils.getElapsedMilliseconds(latencyStartTime),
                              e,
                              exc_info=True)
            raise
    
    """
    netweaver provider check action to query for failed updates metrics
    """
    def _actionGetFailedUpdatesMetrics(self) -> None:
        # base class will always call generateJsonString(), so we must always be sure to set the lastResult
        # regardless of success or failure
        self.lastResult = []

        try:
            # initialize hostname log string here to default of SID in case we cannot identify a specific dispatcher host
            sapHostnameStr = self.providerInstance.sapSid

            if (not self.providerInstance.areRfcMetricsEnabled()):
                self.tracer.info("%s Skipping sys logs metrics because RFC SDK metrics not enabled...", self.logTag)
                return

            # track latency of entire method excecution with dependencies
            latencyStartTime = time()

            # initialize a client for the first healthy MessageServer instance we find
            client = self.providerInstance.getRfcClient(logTag=self.logTag)

            # update logging prefix with the specific instance details of the client
            sapHostnameStr = "%s|%s" % (client.Hostname, client.InstanceNr)
            
            # initialie timezone data for utc offset fetched from SAP server
            sapServerTimeZone = self.providerInstance.getRfcServerTimeZone()

            # get metric query window based on our last successful query where results were returned
            (startTime, endTime) = client.getQueryWindow(lastRunServerTime=self.lastRunServer,
                                                         minimumRunIntervalSecs=self.frequencySecs,
                                                         serverTimeZone=sapServerTimeZone,
                                                         logTag=self.logTag)

            self.lastResult = client.getFailedUpdatesMetrics(logTag=self.logTag)

            self.tracer.info("%s successfully queried failed updates metrics for %s [%d ms]", 
                             self.logTag, sapHostnameStr, TimeUtils.getElapsedMilliseconds(latencyStartTime))
            self.lastRunLocal = datetime.now(timezone.utc)
            self.lastRunServer = endTime

            # only update state on successful query attempt
            self.updateState()

        except Exception as e:
            self.tracer.error("%s exception trying to fetch failed updates metrics for %s [%d ms], error: %s",
                              self.logTag,
                              sapHostnameStr,
                              TimeUtils.getElapsedMilliseconds(latencyStartTime),
                              e,
                              exc_info=True)
            raise

    """
    netweaver provider check action to query for batch job metrics
    """
    def _actionGetBatchJobMetrics(self) -> None:
        # base class will always call generateJsonString(), so we must always be sure to set the lastResult
        # regardless of success or failure
        self.lastResult = []

        try:
            # initialize hostname log string here to default of SID in case we cannot identify a specific dispatcher host
            sapHostnameStr = self.providerInstance.sapSid

            if (not self.providerInstance.areRfcMetricsEnabled()):
                self.tracer.info("%s Skipping batch jobs metrics because RFC SDK metrics not enabled...", self.logTag)
                return

            # track latency of entire method excecution with dependencies
            latencyStartTime = time()

            # initialize a client for the first healthy MessageServer instance we find
            client = self.providerInstance.getRfcClient(logTag=self.logTag)

            # update logging prefix with the specific instance details of the client
            sapHostnameStr = "%s|%s" % (client.Hostname, client.InstanceNr)
            
            # initialie timezone data for utc offset fetched from SAP server
            sapServerTimeZone = self.providerInstance.getRfcServerTimeZone()

            # get metric query window based on our last successful query where results were returned
            (startTime, endTime) = client.getQueryWindow(lastRunServerTime=self.lastRunServer,
                                                         minimumRunIntervalSecs=self.frequencySecs,
                                                         serverTimeZone=sapServerTimeZone,
                                                         logTag=self.logTag)

            self.lastResult = client.getBatchJobMetrics(startDateTime=startTime, endDateTime=endTime, logTag=self.logTag)

            self.tracer.info("%s successfully queried batch job metrics for %s [%d ms]", 
                             self.logTag, sapHostnameStr, TimeUtils.getElapsedMilliseconds(latencyStartTime))
            self.lastRunLocal = datetime.now(timezone.utc)
            self.lastRunServer = endTime

            # only update state on successful query attempt
            self.updateState()

        except Exception as e:
            self.tracer.error("%s exception trying to fetch failed updates metrics for %s [%d ms], error: %s",
                              self.logTag,
                              sapHostnameStr,
                              TimeUtils.getElapsedMilliseconds(latencyStartTime),
                              e,
                              exc_info=True)
            raise

    """
    netweaver provider check action to query for inbound queues statistics
    """
    def _actionGetInboundQueuesMetrics(self) -> None:
        # base class will always call generateJsonString(), so we must always be sure to set the lastResult
        # regardless of success or failure
        self.lastResult = []

        try:
            # initialize hostname log string here to default of SID in case we cannot identify a specific dispatcher host
            sapHostnameStr = self.providerInstance.sapSid

            if (not self.providerInstance.areRfcMetricsEnabled()):
                self.tracer.info("%s Skipping Current Inbound Queues metrics because RFC SDK metrics not enabled...", self.logTag)
                return

            # track latency of entire method excecution with dependencies
            latencyStartTime = time()

            # initialize a client for the first healthy MessageServer instance we find
            client = self.providerInstance.getRfcClient(logTag=self.logTag)

            # update logging prefix with the specific instance details of the client
            sapHostnameStr = "%s|%s" % (client.Hostname, client.InstanceNr)

            self.lastResult = client.getInboundQueuesMetrics(logTag=self.logTag)

            self.tracer.info("%s successfully queried Current Inbound Queues metrics for %s [%d ms]", 
                             self.logTag, sapHostnameStr, TimeUtils.getElapsedMilliseconds(latencyStartTime))
            self.lastRunLocal = datetime.now(timezone.utc)

            # only update state on successful query attempt
            self.updateState()

        except Exception as e:
            self.tracer.error("%s exception trying to fetch Current Inbound Queues metrics for %s [%d ms], error: %s",
                              self.logTag,
                              sapHostnameStr,
                              TimeUtils.getElapsedMilliseconds(latencyStartTime),
                              e,
                              exc_info=True)
            raise


    """
    netweaver provider check action to query for outbound queues statistics
    """
    def _actionGetOutboundQueuesMetrics(self) -> None:
        # base class will always call generateJsonString(), so we must always be sure to set the lastResult
        # regardless of success or failure
        self.lastResult = []

        try:
            # initialize hostname log string here to default of SID in case we cannot identify a specific dispatcher host
            sapHostnameStr = self.providerInstance.sapSid

            if (not self.providerInstance.areRfcMetricsEnabled()):
                self.tracer.info("%s Skipping Current Outbound Queues metrics because RFC SDK metrics not enabled...", self.logTag)
                return

            # track latency of entire method excecution with dependencies
            latencyStartTime = time()

            # initialize a client for the first healthy MessageServer instance we find
            client = self.providerInstance.getRfcClient(logTag=self.logTag)

            # update logging prefix with the specific instance details of the client
            sapHostnameStr = "%s|%s" % (client.Hostname, client.InstanceNr)

            self.lastResult = client.getOutboundQueuesMetrics(logTag=self.logTag)

            self.tracer.info("%s successfully queried Current Outbound Queues metrics for %s [%d ms]", 
                             self.logTag, sapHostnameStr, TimeUtils.getElapsedMilliseconds(latencyStartTime))
            self.lastRunLocal = datetime.now(timezone.utc)

            # only update state on successful query attempt
            self.updateState()

        except Exception as e:
            self.tracer.error("%s exception trying to fetch Current Outbound Queues metrics for %s [%d ms], error: %s",
                              self.logTag,
                              sapHostnameStr,
                              TimeUtils.getElapsedMilliseconds(latencyStartTime),
                              e,
                              exc_info=True)
            raise


    """
    netweaver provider check action to query for object lock entries by connecting to ENQUEUE_READ RFC
    """
    def _actionGetEnqueueReadMetrics(self) -> None:
        # base class will always call generateJsonString(), so we must always be sure to set the lastResult
        # regardless of success or failure
        self.lastResult = []

        try:
            # initialize hostname log string here to default of SID in case we cannot identify a specific dispatcher host
            sapHostnameStr = self.providerInstance.sapSid

            if (not self.providerInstance.areRfcMetricsEnabled()):
                self.tracer.info("%s Skipping ENQUEUE_READ metrics because RFC SDK metrics not enabled...", self.logTag)
                return

            # track latency of entire method excecution with dependencies
            latencyStartTime = time()

            # initialize a client for the first healthy MessageServer instance we find
            client = self.providerInstance.getRfcClient(logTag=self.logTag)

            # initialie timezone data for utc offset fetched from SAP server
            sapServerTimeZone = self.providerInstance.getRfcServerTimeZone()

            # update logging prefix with the specific instance details of the client
            sapHostnameStr = "%s|%s" % (client.Hostname, client.InstanceNr)

            self.lastResult = client.getEnqueueReadMetrics(logTag=self.logTag, serverTimeZone=sapServerTimeZone)

            self.tracer.info("%s successfully queried ENQUEUE_READ metrics for %s [%d ms]", 
                             self.logTag, sapHostnameStr, TimeUtils.getElapsedMilliseconds(latencyStartTime))
            self.lastRunLocal = datetime.now(timezone.utc)

            # only update state on successful query attempt
            self.updateState()

        except Exception as e:
            self.tracer.error("%s exception trying to fetch ENQUEUE_READ metrics for %s [%d ms], error: %s",
                              self.logTag,
                              sapHostnameStr,
                              TimeUtils.getElapsedMilliseconds(latencyStartTime),
                              e,
                              exc_info=True)
            raise

    #####################
    # Provider check helper methods
    #####################

    def _getFormattedTimestamp(self) -> str:
        return datetime.utcnow().isoformat()

    """
    helper method to do following:
        1. filter list SAP system instances down to set that matches specific SAP Feature filter conditions
        2. invoke caller specified SOAP client method against filtered list of SAP instances
        3. santize results using caller specified method to remove PII fields we don't want to ingest to Log Analytics
        4. enrich metrics with common schema properties
        5. results from all instances are appended to a single list and returned
        6. save metric result set and "last run" state into provider check base class variables 
           so that they will be ingested to Log Analytics by sapmon framework
    """
    def _executeSoapApiForInstances(self, 
                                    logTag: str, 
                                    apiName: str,
                                    filterFeatures: list, 
                                    filterType: str,
                                    clientFunc: Callable[[str, NetWeaverSoapClientBase], list],
                                    sanitizeResultsFunc: Callable[[list], list] = None) -> list:
        self.lastRunLocal = datetime.utcnow()
        self.lastRunServer = self.providerInstance.getServerTimestamp(logTag=logTag)
        currentTimestamp = self._getFormattedTimestamp()

        # initialize empty structure to hold validation error aggregate count by category
        allResults = []

        # track latency of entire method excecution with dependencies
        startTime = time()
        
        # Use cached list of instances if available since they don't change that frequently; else fetch afresh.
        # filter down to just the instances we need for this SOAP API type
        sapInstances = self.providerInstance.getInstances(useCache=True, filterFeatures=filterFeatures, filterType=filterType)

        if len(sapInstances) == 0:
            self.tracer.info("%s no instances that support this API: %s", self.logTag, apiName)

        # keep track of total instances called for this API and total errors
        totalCount = 0
        errorCount = 0

        for instance in sapInstances:
            totalCount += 1

            # default to https unless the httpsPort was not defined, in which case fallback to http
            httpProtocol = "https"
            port = instance['httpsPort']
            if ((not port) or port == "0"):
                # fallback to http port instead
                httpProtocol = "http"
                port = instance['httpPort']

            results = []
            try:
                client = MetricClientFactory.getSoapMetricClientForHostAndPort(tracer=self.tracer,
                                                                               logTag=logTag,
                                                                               sapSid=self.providerInstance.sapSid,
                                                                               sapHostName=instance['hostname'],
                                                                               sapSubdomain=self.providerInstance.sapSubdomain,
                                                                               httpProtocol=httpProtocol,
                                                                               httpPort=port,
                                                                               useCache=True)

                # invoke SOAP API for this instance client
                results = clientFunc(logTag, client)

                # if user provided a post-processing method to sanitize raw results, then invoke
                if sanitizeResultsFunc:
                    results = sanitizeResultsFunc(results)

                # decorate results with common metric schema properties
                if len(results) > 0:
                    for result in results:
                        result['hostname'] = instance['hostname']
                        result['instanceNr'] = instance['instanceNr']
                        result['subdomain'] = self.providerInstance.sapSubdomain
                        result['timestamp'] = currentTimestamp
                        result['serverTimestamp'] = self.lastRunServer.isoformat()
                        result['SID'] = self.providerInstance.sapSid
                    allResults.extend(results)

            except Exception as e:
                errorCount += 1
                # log the fully qualified hostname and exception
                wsdlUrl = NetWeaverSoapClient._getFullyQualifiedWsdl(instance['hostname'], self.providerInstance.sapSubdomain, httpProtocol, port)
                self.tracer.error("%s exception trying to call SOAP API %s url: %s, %s", logTag, apiName, wsdlUrl, e, exc_info=True)
                continue

        self.lastResult = allResults

        self.tracer.info("%s finished SOAP API: %s, %d results from %d instances with %d errors [%d ms]",
                         logTag, apiName, len(allResults), totalCount, errorCount, TimeUtils.getElapsedMilliseconds(startTime))

        if not self.updateState():
            raise Exception("%s failed to update state for web service request for SOAP API: %s" % (logTag, apiName))
            
        return allResults

    """
    Method to parse the value based on the key provided and set the values with None value to empty string ''
    """
    def _getKeyValue(self, dictionary, key, apiName):
            if key not in dictionary:
                raise ValueError("Result received for api %s does not contain key: %s"% (apiName, key))
            if(dictionary[key] == None):
                dictionary[key] = ""
            return dictionary[key]

    """
    Method to parse the results from ABAPGetWPTable and set the strings with None value to empty string ''
    """
    def _sanitizeABAPGetWPTable(self, records: list) -> list:
       apiName = "ABAPGetWPTable"
       processed_results = list()
       for record in records:
            processed_result = {
                "Action": self._getKeyValue(record, 'Action', apiName),
                "Client": self._getKeyValue(record, 'Client', apiName),
                "Cpu": self._getKeyValue(record, 'Cpu', apiName),
                "Err": self._getKeyValue(record, 'Err', apiName),
                "No": self._getKeyValue(record, 'No', apiName),
                "Pid": self._getKeyValue(record, 'Pid', apiName),
                "Program": self._getKeyValue(record, 'Program', apiName),
                "Reason": self._getKeyValue(record, 'Reason', apiName),
                "Sem": self._getKeyValue(record, 'Sem', apiName),
                "Start": self._getKeyValue(record, 'Start', apiName),
                "Status": self._getKeyValue(record, 'Status', apiName),
                "Table": self._getKeyValue(record, 'Table', apiName),
                "Time": self._getKeyValue(record, 'Time', apiName),
                "Typ": self._getKeyValue(record, 'Typ', apiName),
                "User": self._getKeyValue(record, 'User', apiName)
            }
            processed_results.append(processed_result)
       return processed_results

    """
    Method to parse the results from GetProcessList and set the strings with None value to empty string ''
    """
    def _sanitizeGetProcessList(self, records: list) -> list:
       apiName = "GetProcessList"
       processed_results = list()
       for record in records:
            processed_result = {
                "description": self._getKeyValue(record, 'description', apiName),
                "dispstatus": self._getKeyValue(record, 'dispstatus', apiName),
                "elapsedtime": self._getKeyValue(record, 'elapsedtime', apiName),
                "name": self._getKeyValue(record, 'name', apiName),
                "pid": self._getKeyValue(record, 'pid', apiName),
                "starttime": self._getKeyValue(record, 'starttime', apiName),
                "textstatus": self._getKeyValue(record, 'textstatus', apiName)
            }
            processed_results.append(processed_result)
       return processed_results

    """
    Method to parse results from response of GetEnvironment api call (just computerName for now)
    """
    def _sanitizeGetEnvironmentDetails(self, records: List[str]) -> list:
        computerName = None
        for record in records:
            #get COMPUTERNAME from Windows VM or HOSTNAME from Linux VM
            if(record.__contains__('COMPUTERNAME') or record.__contains__('HOSTNAME')):
                computerName = record.split('=')[1]
                break            
        if(computerName):
            return [{"computerName" : computerName}]
        else:
            self.tracer.info("%s No COMPUTERNAME or HOST found in data: %s", self.logTag, records)

    """
    Method to process aggregated results from GetEnvironment and map computerName with corresponding azure resource id
    """
    def _postProcessGetEnvironmentResults(self, sapResources: List[Dict]) -> List[Dict]:
        try:
            sapAzResourceMapping = self._getSapAzResourceMapping(sapResources)
            if not self._updateStateWithSapAzMapping(sapAzResourceMapping):
                raise Exception("%s failed to update Azure Resource mapping in state file" % (self.logTag))
            self.tracer.info("%s successfully updated Azure Resource mapping in state file. Count: %s", self.logTag, len(sapAzResourceMapping))
            return sapAzResourceMapping
        except Exception as e: 
            self.tracer.error("%s Failed to process GetEnvironment Results for SAP Resources \n----\n%s\n----\n (%s)" % (self.logTag, sapResources, e), exc_info=True)
            raise

    """
    Method to get a mapping between SAP instance and Azure resource id
    """
    def _getSapAzResourceMapping(self, sapResources: List[Dict]) -> List[Dict]:
        vNetIds = None
        aiopsInstance = list(filter(
            lambda x: x.providerType == AIOPS_PROVIDER_TYPE, self.providerInstance.ctx.instances))
        if( len(aiopsInstance) != 0):
            vNetIds = aiopsInstance[0].vNetIds
        computerNames = [sapResource["computerName"] for sapResource in sapResources]
        self.tracer.info("%s Fetching Azure Resource details using Azure Resource Graph with computerNames: %s and vNetIds: %s", self.logTag, computerNames, vNetIds)
        azResources = self._getAzResourceId(computerNames, vNetIds)

        #join sapResource and azResource data using computerName
        self.tracer.info("%s Data berore merging: SAP Resources = %s | Azure Resources = %s", self.logTag, sapResources, azResources)
        mergedResources = self._joinDataSets(sapResources, azResources, "computerName")
        self.tracer.info("%s Data after merging = %s", self.logTag, mergedResources)
        return mergedResources

    """
    Method to update state file with instanceName-azResourceId mapping
    """
    def _updateStateWithSapAzMapping(self, sapAzResourceMapping: List[Dict]) -> bool:
        processedSapAzResourceMapping = {}

        if( not any('id' in resource for resource in sapAzResourceMapping)):
            self.tracer.info("%s Did not update state with sapAzMapping. No azResourceId found.", self.logTag)
            return False

        self.tracer.info("%s Grouping resource mapping results by armType and instance name")
        #Group resources by (arm)Type and map instanceName with SID, azResourceID 
        for resource in sapAzResourceMapping:
            armType = resource.get("type")
            instanceName = resource.get("hostname") + "_" + str(resource.get("instanceNr")).zfill(2)
            value = {
                "SID": resource.get("SID"),
                "azResourceId": resource.get("id")}
            processedSapAzResourceMapping.setdefault(armType, {})
            processedSapAzResourceMapping[armType][instanceName] = value

        #Replce missing azResourceId values with old value in azResourceConfig. (values could be missing if required vnets are not added to key vault secret)
        self.providerInstance.state.setdefault("azResourceConfig", {})
        for resourceType in processedSapAzResourceMapping:
            currentMapping = self.providerInstance.state.get("azResourceConfig").get(resourceType)
            for resource in processedSapAzResourceMapping[resourceType]:
                if(not processedSapAzResourceMapping[resourceType][resource].get("azResourceId") and resource in currentMapping):
                    processedSapAzResourceMapping[resourceType][resource]["azResourceId"] = currentMapping[resource]["azResourceId"]
            self.providerInstance.state["azResourceConfig"][resourceType] = processedSapAzResourceMapping[resourceType]
        self.tracer.info("%s SAP Host - Azure Resource ID mapping: %s", self.logTag, self.providerInstance.state["azResourceConfig"])
        return True

    """
    Method to get Azure resource id using SAP computerNames and vNetIds
    """
    def _getAzResourceId(self, computerNames: List[str], vNetIds: List[str]) -> List[Dict[str, str]]:
        aiopsHelper = AIOpsHelperFactory.getAIOpsHelper(self.tracer, self.providerInstance.ctx)
        azResources = aiopsHelper.getVMComputerNameToAzResourceIdMapping(computerNames, vNetIds)
        return azResources

    """
    Helper method to join two lists of dictionaries (datasets) by a key (left outer join)
    """
    def _joinDataSets(self, dataSet1: List[Dict], dataSet2: List[Dict], key: str) -> List[Dict]:
        if( not dataSet1):
            return None
        if(not dataSet2):
            return dataSet1
        dataFrame1 = DataFrame(dataSet1)
        dataFrame2 = DataFrame(dataSet2)
        mergedDataFrame = merge(dataFrame1, dataFrame2, on = key, how = 'left')
        return mergedDataFrame.to_dict('records')

    def generateJsonString(self) -> str:
        self.tracer.info("%s converting result to json string", self.logTag)
        if self.lastResult is not None and len(self.lastResult) != 0:
            for result in self.lastResult:
                result['SAPMON_VERSION'] = PAYLOAD_VERSION
                result['PROVIDER_INSTANCE'] = self.providerInstance.name
                result['METADATA'] = self.providerInstance.metadata
    
        resultJsonString = json.dumps(self.lastResult, sort_keys=True, indent=4, cls=JsonEncoder)
        self.tracer.debug("%s resultJson=%s", self.logTag, str(resultJsonString))
        return resultJsonString

    def updateState(self) -> bool:
        self.tracer.info("%s updating internal state", self.logTag)
        self.state['lastRunLocal'] = self.lastRunLocal
        self.state['lastRunServer'] = self.lastRunServer
        self.tracer.info("%s internal state successfully updated", self.logTag)
        return True
