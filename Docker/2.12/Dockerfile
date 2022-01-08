FROM python@sha256:b21b91c9618e951a8cbca5b696424fa5e820800a88b7e7afd66bba0441a764d6

ARG RELEASE
RUN apt-get update -y
RUN apt-get install curl gnupg -y

# Note: -k/--insecure cannot be used with curl; security compliance requires we verify certs
RUN curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
RUN curl https://packages.microsoft.com/config/debian/10/prod.list > /etc/apt/sources.list.d/mssql-release.list
RUN apt-get update -y
RUN apt-get upgrade -y
RUN apt-get install git -y
RUN apt-get install git gcc libffi-dev g++ unixodbc-dev -y
RUN pip3 install --upgrade pip
RUN pip3 install msrestazure==0.6.4 hdbcli azure-storage==0.36.0 azure_storage_logging azure-mgmt-storage==16.0.0 azure-keyvault-secrets azure-identity prometheus_client retry pyodbc pandas zeep

# dynamic library load path must be set to the anticipated install path of the RFC SDK libraries
# and the directory must exist before the python process is started up.  This will allow us
# to optionally install RFC SDK files at sapmon runtime and then be able to successfully import
# pyrfc module without restarting python process
RUN mkdir -p /var/opt/microsoft/sapmon/${RELEASE}/sapmon/usrlibs/nwrfcsdk/nwrfcsdk/lib
ENV LD_LIBRARY_PATH=/var/opt/microsoft/sapmon/${RELEASE}/sapmon/usrlibs/nwrfcsdk/nwrfcsdk/lib

# download and install Python NW RFC connector package so it is available for import if RFC SDK is installed
RUN curl --location --output pynwrfc-2.3.0-cp37-cp37m-linux_x86_64.whl https://github.com/SAP/PyRFC/releases/download/2.3.0/pynwrfc-2.3.0-cp37-cp37m-linux_x86_64.whl
RUN pip3 install pynwrfc-2.3.0-cp37-cp37m-linux_x86_64.whl

RUN ACCEPT_EULA=Y apt-get install msodbcsql17 -y
RUN mkdir -p /var/opt/microsoft/sapmon/${RELEASE}
RUN git clone https://github.com/Azure/AzureMonitorForSAPSolutions.git --branch ${RELEASE} ${RELEASE}
RUN cp -a ${RELEASE}/* /var/opt/microsoft/sapmon/${RELEASE}
CMD []