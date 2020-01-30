# Azure modules
from azure.common.credentials import BasicTokenAuthentication
from azure.mgmt.storage import StorageManagementClient

# Python modules
import base64
import hashlib
import hmac
import json
import logging
import requests
import sys
from typing import Callable, Dict, Optional

# Payload modules
from const import *
from helper.tools import *

###############################################################################

# Provide access to Azure Instance Metadata Service (IMDS) inside the collector VM
class AzureInstanceMetadataService:
   uri = "http://169.254.169.254/metadata"
   params = {"api-version": "2018-02-01"}
   headers = {"Metadata": "true"}

   # Send a request to the IMDS endpoint
   @staticmethod
   def _sendRequest(tracer: logging.Logger,
                    endpoint: str,
                    params: Optional[Dict[str, str]] = {},
                    headers: Optional[Dict[str, str]] = {}) -> bytes:
      # Add IMDS-specific query parameters and HTTP headers
      params.update(AzureInstanceMetadataService.params)
      headers.update(AzureInstanceMetadataService.headers)
      return REST.sendRequest(tracer,
                              "%s/%s" % (AzureInstanceMetadataService.uri, endpoint),
                              params = params,
                              headers = headers)

   # Call IMDS to get the compute instance of the collector VM
   @staticmethod
   def getComputeInstance(tracer: logging.Logger,
                          operation: str) -> Dict[str, str]:
      tracer.info("getting compute instance")      
      computeInstance = None
      try:
         computeInstance = AzureInstanceMetadataService._sendRequest(tracer,
            "instance",
            headers = {"User-Agent": "SAP Monitor/%s (%s)" % (PAYLOAD_VERSION, operation)}
            )["compute"]
         tracer.debug("computeInstance=%s" % computeInstance)
      except Exception as e:
         tracer.error("could not obtain instance metadata (%s)" % e)
      return computeInstance

   # Get an authentication token via IMDS
   @staticmethod
   def getAuthToken(tracer: logging.Logger,
                    resource: str,
                    msiClientId: Optional[str] = None) -> str:
      tracer.info("getting auth token for resource=%s%s" % (resource, ", msiClientId=%s" % msiClientId if msiClientId else ""))
      authToken = None
      try:
         authToken = AzureInstanceMetadataService._sendRequest(
            tracer,
            "identity/oauth2/token",
            params = {"resource": resource, "client_id": msiClientId}
            )["access_token"]
      except Exception as e:
         tracer.critical("could not get auth token (%s)" % e)
         sys.exit(ERROR_GETTING_AUTH_TOKEN)
      return authToken

###############################################################################

# Provide access to an Azure KeyVault instance
class AzureKeyVault:
   headers = None
   kvName = None
   params = {"api-version": "7.0"}
   token = None
   tracer = None
   uri = None

   def __init__(self,
                tracer: logging.Logger,
                kvName: str,
                msiClientId: Optional[str] = None):
      self.tracer = tracer
      self.tracer.info("initializing KeyVault %s" % kvName)
      self.kvName = kvName
      self.uri = "https://%s.vault.azure.net" % kvName
      self.token = AzureInstanceMetadataService.getAuthToken(self.tracer,
                                                             "https://vault.azure.net",
                                                             msiClientId = msiClientId)
      self.headers = {
         "Authorization": "Bearer %s" % self.token,
         "Content-Type":  "application/json"
         }

   # Easy access to KeyVault REST endpoints
   def _sendRequest(self,
                    endpoint: str,
                    method: Callable = requests.get,
                    data: Optional[bytes] = None) -> (bool, str):
      response = REST.sendRequest(self.tracer,
                                  endpoint,
                                  method = method,
                                  params = self.params,
                                  headers = self.headers,
                                  data = data)
      if response and "value" in response:
         return (True, response["value"])
      return (False, None)

   # Set a secret in the KeyVault
   def setSecret(self,
                 secretName: str,
                 secretValue: str) -> bool:
      self.tracer.info("setting KeyVault secret for secretName=%s" % secretName)
      success = False
      try:
         (success, response) = self._sendRequest("%s/secrets/%s" % (self.uri, secretName),
                                                 method = requests.put,
                                                 data   = json.dumps({"value": secretValue}))
      except Exception as e:
         self.tracer.critical("could not set KeyVault secret (%s)" % e)
         sys.exit(ERROR_SETTING_KEYVAULT_SECRET)
      return success

   # Get the current version of a specific secret in the KeyVault
   def getSecret(self,
                 secretId: str) -> bool:
      self.tracer.info("getting KeyVault secret for secretId=%s" % secretId)
      secret = None
      try:
         (success, secret) = self._sendRequest(secretId)
      except Exception as e:
         self.tracer.error("could not get KeyVault secret for secretId=%s (%s)" % (secretId, e))
      return secret

   # Get the current versions of all secrets inside the customer KeyVault
   def getCurrentSecrets(self) -> Dict[str, str]:
      self.tracer.info("getting current KeyVault secrets")
      secrets = {}
      try:
         (success, kvSecrets) = self._sendRequest("%s/secrets" % self.uri)
         self.tracer.debug("kvSecrets=%s" % kvSecrets)
         for k in kvSecrets:
            id = k["id"].split("/")[-1]
            secrets[id] = self.getSecret(k["id"])
      except Exception as e:
         self.tracer.error("could not get current KeyVault secrets (%s)" % e)
      return secrets

   # Check if a KeyVault with a specified name exists
   def exists(self) -> bool:
      self.tracer.info("checking if KeyVault %s exists" % self.kvName)
      try:
         (success, response) = self._sendRequest("%s/secrets" % self.uri)
      except Exception as e:
         self.tracer.error("could not determine is KeyVault %s exists (%s)" % (self.kvName, e))
      if success:
         self.tracer.info("KeyVault %s exists" % self.kvName)
      else:
         self.tracer.info("KeyVault %s does not exist" % self.kvName)
      return success

###############################################################################

# Provide access to an Azure Log Analytics Workspace
class AzureLogAnalytics:
   sharedKey = None
   tracer = None
   uri = None
   workspaceId = None

   def __init__(self,
                tracer: logging.Logger,
                workspaceId: str,
                sharedKey: str):
      self.tracer = tracer
      self.tracer.info("initializing Log Analytics instance")
      self.workspaceId = workspaceId
      self.sharedKey = sharedKey
      self.uri = "https://%s.ods.opinsights.azure.com/api/logs?api-version=2016-04-01" % workspaceId

   # Ingest JSON content as custom log via Log Analytics Data Collector API
   # https://docs.microsoft.com/en-us/azure/azure-monitor/platform/data-collector-api
   def ingest(self,
              customLog: str,
              jsonData: str,
              colTimeGenerated: str) -> bytes:

      # Sign the content as required by Data Collector API
      def buildSig(content: str,
                   timestamp: str) -> str:
         stringHash  = """POST
%d
application/json
x-ms-date:%s
/api/logs""" % (len(content), timestamp)
         bytesHash = bytes(stringHash, encoding="utf-8")
         decodedKey = base64.b64decode(self.sharedKey)
         encodedHash = base64.b64encode(hmac.new(decodedKey,
                                                 bytesHash,
                                                 digestmod = hashlib.sha256).digest())
         stringHash = encodedHash.decode("utf-8")
         return "SharedKey %s:%s" % (self.workspaceId, stringHash)

      self.tracer.info("ingesting telemetry into Log Analytics, custom log %s" % customLog)

      # Log Analytics expects a specific time format
      timestamp = datetime.utcnow().strftime(TIME_FORMAT_LOG_ANALYTICS)
      headers = {
         "content-type":  "application/json",
         "Authorization": buildSig(jsonData, timestamp),
         "Log-Type":      customLog,
         "x-ms-date":     timestamp,
         "time-generated-field": colTimeGenerated
      }
      self.tracer.debug("data=%s" % jsonData)
      response = None

      # Ingest the actual content via Data Collector API
      try:
         response = REST.sendRequest(self.tracer,
                                     self.uri,
                                     method = requests.post,
                                     headers = headers,
                                     data = jsonData)
      except Exception as e:
         self.tracer.error("could not ingest telemetry into Log Analytics (%s)" % e)

      return response

###############################################################################

# Provide access to an Azure Storage Queue (used for payload logging)
class AzureStorageQueue():
    accountName = None
    name = None
    resourceGroup = None
    subscriptionId = None
    token = {}
    tracer = None

    # Retrieve the name of the storage account and storage queue
    def __init__(self,
                 tracer: logging.Logger,
                 sapmonId: str,
                 msiClientID: str,
                 subscriptionId: str,
                 resourceGroup: str,
                 queueName: str):
        self.tracer = tracer
        self.tracer.info("initializing Storage Queue instance")
        self.accountName = STORAGE_ACCOUNT_NAMING_CONVENTION % sapmonId
        self.name = queueName
        tokenResponse = AzureInstanceMetadataService.getAuthToken(self.tracer,
                                                                  resource = "https://management.azure.com/",
                                                                  msiClientId = msiClientID)
        self.token["access_token"] = tokenResponse
        self.subscriptionId = subscriptionId
        self.resourceGroup = resourceGroup

    # Get the access key to the storage queue
    def getAccessKey(self) -> str:
        self.tracer.info("getting access key for Storage Queue")
        storageclient = StorageManagementClient(credentials = BasicTokenAuthentication(self.token),
                                                subscription_id = self.subscriptionId)

        # Retrieve keys from storage accounts
        storageKeys = storageclient.storage_accounts.list_keys(resource_group_name = self.resourceGroup,
                                                               account_name = self.accountName)
        if storageKeys is None or len(storageKeys.keys) == 0 :
           self.log.error("could not retrieve storage keys of the storage account %s" % self.accountName)
           return None
        return storageKeys.keys[0].value
