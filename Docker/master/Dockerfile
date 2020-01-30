FROM ubuntu:16.04

ARG RELEASE
RUN apt-get -y update
RUN apt-get install -y python3-pip git
RUN python3 -m pip install -U pip
RUN pip3 install pyhdb azure_storage_logging azure-mgmt-storage
RUN mkdir -p /var/opt/microsoft/sapmon/${RELEASE}
RUN git clone https://github.com/Azure/AzureMonitorForSAPSolutions.git --branch ${RELEASE} ${RELEASE}
RUN cp -a ${RELEASE}/sapmon/* /var/opt/microsoft/sapmon/${RELEASE}
CMD []
