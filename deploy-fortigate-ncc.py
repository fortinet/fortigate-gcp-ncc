import os
import time
import requests,ssl
import argparse
import sys
import json, re
import getpass
from pprint import pprint

import logging
logging.captureWarnings(True)
logger = logging.getLogger('ncc_app')
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)-4s - %(message)s'))
logger.addHandler(stream_handler)
logger.setLevel(logging.DEBUG)

import googleapiclient.discovery
from googleapiclient import discovery
from six.moves import input
from pprint import pprint
from urllib import request, parse
from  urllib.request import urlopen

import urllib.request
import google.auth
from google.oauth2 import service_account
from oauth2client.client import GoogleCredentials

from urllib.parse import urlencode


from google.cloud import storage

import time
import json
import jwt
import requests
import httplib2

SCOPES = ['https://www.googleapis.com/auth/cloud-platform']
AUTH_URL = "https://www.googleapis.com/oauth2/v4/token"



class GCPComputeClient:
    """Creates a GCP Compute Client tailored for Google NCC deployment."""

    def __init__(self, ncc_info, service_account_file):
        self.ncc_info = ncc_info
        self.service_account_file = service_account_file
        self.compute_client = self._build_compute_client()
        return

    def _build_compute_client(self):
        ''' Create google compute client from the service acccount file '''

        credentials = service_account.Credentials.from_service_account_file(
        self.service_account_file, scopes=SCOPES)
        return googleapiclient.discovery.build('compute', 'v1', credentials=credentials)


    def create_instance(self,spoke_publicip):
        ''' Create a FortiGate instance in GCP Compute '''
        
        ncc_info = self.ncc_info
        fgt_pass = ncc_info['fortigate_pwd']
        bgp_as= ncc_info['fortigate_router_asn']
        bgp_router_id = ncc_info['fortigate_router_id']
        ca_asn = ncc_info['cloud_router_asn']
        image_response = self.compute_client.images().get(project='fortigcp-project-001', image='fortinet-fgtondemand-700-20210407-001-w-license')
        routemap_data = "config router route-map\n edit 'nexthop1'\n config rule\n edit 1\n set set-ip-nexthop "+ ncc_info['cloud_router_ip1'] + "\n unset set-ip6-nexthop\n\n unset set-ip6-nexthop-local\n unset set-originator-id\n next \n end \n next \n edit 'nexthop2'\n config rule\n edit 1\n set set-ip-nexthop " + ncc_info['cloud_router_ip2'] + "\n unset set-ip6-nexthop\n unset set-ip6-nexthop-local\n unset set-originator-id\n next \n end \n next \n end \n"
        userdata = "config system admin\n edit admin\n set password " + fgt_pass + "\n set force-password-change enable \n next\n end\n\n "+ routemap_data +"\n config router bgp\n set as " + bgp_as + "\n set router-id " + bgp_router_id + "\n config neighbor \n edit " + ncc_info['cloud_router_ip1'] + "\nset remote-as " + ca_asn + "\nset ebgp-enforce-multihop enable\n set soft-reconfiguration enable\n set route-map-in 'nexthop1'\n next \n edit " + ncc_info['cloud_router_ip2'] + "\nset remote-as " + ca_asn + "\nset ebgp-enforce-multihop enable\n set soft-reconfiguration enable\n set route-map-in 'nexthop2'\n\nnext \nend \n config network\n edit 1\n set prefix " + ncc_info['ncc_vpc_int_cidr'] + "\n next \n end \n end\n"
        logger.info("userdata: %s", userdata)

        source_disk_image = image_response.uri

        # Configure the machine
        machine_type = "zones/%s/machineTypes/n1-standard-4" % ncc_info['zone']
        metadata = {

            "items": [
                {
                  "key" :"user-data",
                  "value": userdata
                                   },
                # {
                #     "key": "fortigate_user_password",
                #     "value": password
                # },

                {
                    "key": "google-monitoring-enable",
                    "value": "0"
                },
                {
                    "key": "google-logging-enable",
                    "value": "0"
                }
            ],
        }
        config = {
            'name': ncc_info['fortigate_spoke1'],
            'machineType': machine_type,
            'metadata':metadata,
            "canIpForward": True,
            # Specify the boot disk and the image to use as a source.
            'disks': [
                {
                    'boot': True,
                    'autoDelete': True,
                    'initializeParams': {
                        'sourceImage': source_disk_image,
                    }
                }
            ],

            # Specify a network interface with NAT to access the public
            # internet.
            'networkInterfaces': [
                {
                'network':  "projects/" + ncc_info['project'] + "/global/networks/" + ncc_info['ncc_vpc_ext'],
                "subnetwork": "projects/" + ncc_info['project'] + "/regions/" + ncc_info['region'] +"/subnetworks/" + ncc_info['region']+'-'+ncc_info['ncc_vpc_ext'],
                'accessConfigs': [
                    {'type': 'ONE_TO_ONE_NAT', 'name': 'External NAT', "natIP": spoke_publicip }
                ]
            },
                {
                    'network':  "projects/" + ncc_info['project'] + "/global/networks/" + ncc_info['ncc_vpc_int'],
                    "subnetwork": "projects/" + ncc_info['project'] + "/regions/" + ncc_info['region'] +"/subnetworks/" + ncc_info['region']+'-'+ncc_info['ncc_vpc_int'],
                },
            ],

            # Allow the instance to access cloud storage and logging.
            'serviceAccounts': [{
                'email': 'default',
                'scopes': [
                    'https://www.googleapis.com/auth/devstorage.read_write',
                    'https://www.googleapis.com/auth/logging.write'
                ]
            }]

        }
        response = self.compute_client.instances().insert(
            project=ncc_info['project'],
            zone=ncc_info['zone'],
            body=config).execute()
        logger.debug("instance create response received: %s", response)
        return response

    def instance_exists(self, name):
        try:
            ncc_info = self.ncc_info
            request = self.compute_client.instances().get(project=ncc_info['project'], zone=ncc_info['zone'], instance=name)
            response = request.execute()
            return True if response.get('id') else False
        except:
            return False

    def get_instance( self, name):

        ncc_info = self.ncc_info
        output = dict()
        request = self.compute_client.instances().get(project=ncc_info['project'], zone=ncc_info['zone'], instance=name)
        response = request.execute()
        output['ra_ip'] = response['networkInterfaces'][0]['networkIP']
        output['ra_link'] = response['selfLink']
        output['ra_public_ip'] = response['networkInterfaces'][0]['accessConfigs'][0]['natIP']
        return output


    def create_gcp_fw_ingress(self, network):
        ncc_info = self.ncc_info
        name = network + "-in"
        firewall_body={
                  "allowed": [
                    {
                      "IPProtocol": "all"
                    }
                  ],
                  "direction": "INGRESS",
                  "name": name,
                  "network": "projects/" + ncc_info['project'] + "/global/networks/" + network,
                  "priority": 1000.0,
                  "sourceRanges": [
                    "0.0.0.0/0"
                  ]
                }
        request = self.compute_client.firewalls().insert(project=ncc_info['project'], body=firewall_body)
        response = request.execute()


    def create_gcp_fw_egress(self, network):
        ncc_info = self.ncc_info
        name = network + "-out"
        firewall_body={
                  "allowed": [
                    {
                      "IPProtocol": "all"
                    }
                  ],
                  "direction": "EGRESS",
                  "name": name,
                  "network": "projects/" + ncc_info['project']+ "/global/networks/" + network,
                  "priority": 1000.0
                }

        request = self.compute_client.firewalls().insert(project=ncc_info['project'], body=firewall_body)
        response = request.execute()


    def create_vpc(self, vpc_name):

        network_body = { "name": vpc_name, "autoCreateSubnetworks": "False" }
        request = self.compute_client.networks().insert(project=self.ncc_info['project'], body=network_body)
        response = request.execute()
        
        logger.debug("VPC create response received: %s" %response)
        return response


    def create_subnets(self, vpc_name, subnetwork_name, subnetwork_cidr):

        ncc_info = self.ncc_info
        network ="projects/" + ncc_info['project'] + "/global/networks/" + vpc_name
        subnetwork_body = { "name": subnetwork_name, "ipCidrRange": subnetwork_cidr,"network": network }
        request = self.compute_client.subnetworks().insert(project=ncc_info['project'], region=ncc_info['region'], body=subnetwork_body)
        response = request.execute()
        return response

    # Creation of a Static Public IP to assign to the Fortigate Instance
    def create_publicip(self):
        status = self.get_publicip('status')
        if status == 'RESERVED':
            logger.debug("Public IP with the name %s already exists and is NOT in Use", ncc_info['fortigate_spoke1_extip'])
        elif status == 'IN_USE':
            logger.debug("Public IP with the name %s exists and is already IN Use, Please provide a new Public IP name", ncc_info['fortigate_spoke1_extip'])
            logger.debug("Exiting...")
            exit(1)
        elif status == 'None':
            address_body = {"name": self.ncc_info['fortigate_spoke1_extip']}
            request = self.compute_client.addresses().insert(project=ncc_info['project'], region=self.ncc_info['region'], body=address_body)
            response = request.execute()
            logger.debug("Creating Public IP with the name %s ... ", ncc_info['fortigate_spoke1_extip'])
            gcp_compute_client.wait_for_subnetwork_operation(response['name'])
            time.sleep(1)
            logger.debug("Created Public IP with the name %s ... ", ncc_info['fortigate_spoke1_extip'])
            return response



    # Get public IP function supports 2 inputs, 'status' - Gives the status of PIP, and 'address' - that gives you the address string.
    def get_publicip(self,var):
        try:
            request = self.compute_client.addresses().get(project=self.ncc_info['project'], region=self.ncc_info['region'], address=self.ncc_info['fortigate_spoke1_extip'])
            response = request.execute()
            result = response[var.lower()]
            return result
        except :
            return 'None'

    def wait_for_instance_operation(self, operation):
        logger.info("Waiting for instance to become ready")
        while True:
            result = self.compute_client.zoneOperations().get(
                project=self.ncc_info['project'],
                zone=self.ncc_info['zone'],
                operation=operation).execute()

            if result['status'] == 'DONE':
                logger.debug("Instance operation is done.")
                if 'error' in result:
                    logger.error("Error while waiting for the operation to complete", exc_info=True)
                    raise Exception(result['error'])
                return result

            time.sleep(1)


    def wait_for_network_operation(self, operation):
        while True:
            result = self.compute_client.globalOperations().get(
                project=self.ncc_info['project'],
                operation=operation).execute()

            if result['status'] == 'DONE':
                logger.debug("Network operation is done.")
                if 'error' in result:
                    logger.error("Error while waiting for the operation to complete", exc_info=True)
                    raise Exception(result['error'])
                return result

            time.sleep(1)


    def wait_for_subnetwork_operation(self, operation):
        while True:
            result = self.compute_client.regionOperations().get(
                project=self.ncc_info['project'],
                region=self.ncc_info['region'],
                operation=operation).execute()

            if result['status'] == 'DONE':
                logger.debug("Subnetwork operation is done.")
                if 'error' in result:
                    logger.error("Error while waiting for the operation to complete", exc_info=True)
                    raise Exception(result['error'])
                return result

            time.sleep(1)

    def vpc_exists(self,vpc_name):
        try:
            request = self.compute_client.networks().get(project=self.ncc_info['project'], network=vpc_name)
            response = request.execute()
            return True if response.get('id') else False
        except :
            return False

    def subnet_exists(self,subnet_name):
        try:
            request = self.compute_client.subnetworks().get(project=self.ncc_info['project'], region=self.ncc_info['region'], subnetwork=subnet_name)
            response = request.execute()
            return True if response.get('id') else False
        except :
            return False


class GCPRestClient:
    """Creates a GCP REST Client."""

    # Set how long this token will be valid in seconds
    EXPIRES_IN = 3600   # Expires in 1 hour

    def __init__(self, ncc_info, service_account_file):
        self.ncc_info = ncc_info
        self.service_account_file = service_account_file
        self.bearer_token = self._acquire_bearer_token()
        return

    def _load_json_credentials(self, filename):
        ''' Load the Google Service Account Credentials from Json file '''

        with open(filename, 'r') as f:
            data = f.read()

        return json.loads(data)


    def _load_private_key(self, json_cred):
        ''' Return the private key from the json credentials '''

        return json_cred['private_key']

    
    def _create_signed_jwt(self, pkey, pkey_id, email, scope):
        '''
        Create a Signed JWT from the service account Json credentials file
        This Signed JWT will later on be exchanged for an Access Token
        '''

        # This is the Google Endpoint for creating OAuth 2.0 Access Tokens from a Signed-JWT

        issued = int(time.time())
        expires = issued + GCPRestClient.EXPIRES_IN   # expires_in is in seconds

        # Note: this token expires and cannot be refreshed. The token must be recreated

        # JWT Headers
        additional_headers = {
                'kid': pkey_id,
                "alg": "RS256",
                "typ": "JWT"    # Google uses SHA256withRSA
        }

        # JWT Payload
        payload = {
            "iss": email,       # Issuer claim
            "sub": email,       # Issuer claim
            "aud": AUTH_URL,    # Audience claim
            "iat": issued,      # Issued At claim
            "exp": expires,     # Expire time
            "scope": scope      # Permissions
        }

        # Encode the headers and payload and sign creating a Signed JWT (JWS)
        sig = jwt.encode(payload, pkey, algorithm="RS256", headers=additional_headers)

        return sig   


    def _exchangeJwtForAccessToken(self, signed_jwt):
        '''
        This method takes a Signed JWT and exchanges it for a Google OAuth Access Token
        '''
        params = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": signed_jwt
        }

        response = requests.post(AUTH_URL, data=params)

        if response.ok:
            return(response.json()['access_token'], '')

        return None, response.text

    def _acquire_bearer_token(self):
        cred = self._load_json_credentials(self.service_account_file)

        private_key = self._load_private_key(cred)

        signed_jwt = self._create_signed_jwt(
                private_key,
                cred['private_key_id'],
                cred['client_email'],
                SCOPES[0])

        access_token, err = self._exchangeJwtForAccessToken(signed_jwt)

        if access_token is None:
            logger.error("invalid access token: %s", err)
            exit(1)

        return access_token


    def create_hub(self):
        url = "https://networkconnectivity.googleapis.com/v1/projects/" + self.ncc_info['project'] + "/locations/global/hubs/?hub_id=" + self.ncc_info['ncc_hub']
        header = {'Authorization': 'Bearer ' + self.bearer_token}
        response = requests.post(url, headers=header)
        logger.debug("NCC hub created: %s", response.json())
        

    def create_spoke(self, ra_ip, ra, sitetositeData):
        ncc_info = self.ncc_info
        url = "https://networkconnectivity.googleapis.com/v1/projects/" + ncc_info['project'] + "/locations/" + ncc_info['region'] + "/spokes/?spoke_id=" + ncc_info['fortigate_spoke1']

        auth_token = self.bearer_token
        data = {
            "name": ncc_info['fortigate_spoke1'],
            "hub": "http://networkconnectivity.googleapis.com/v1/projects/" + ncc_info['project'] + "/locations/global/hubs/" + ncc_info['ncc_hub'],
            "linkedRouterApplianceInstances": {
                "instances": [
                {
                    "virtualMachine": ra,
                    "ipAddress": ra_ip
                }
                ],
                "siteToSiteDataTransfer" : sitetositeData
            }
        }
        header = {'Authorization': 'Bearer ' + auth_token}
        response = requests.post(url, json=data, headers=header)
        logger.debug("Successfully registered a spoke with NCC hub: %s", response.json())


    def create_cloud_router(self, ra_ip, ra):
        ncc_info = self.ncc_info
        url = "https://www.googleapis.com/compute/beta/projects/" + ncc_info['project'] + "/regions/" + ncc_info['region'] + "/routers"
        int1 = ncc_info['cloud_router'] + "-0"
        int2 = ncc_info['cloud_router'] + "-1"
        bgp_peer1= ncc_info['cloud_router'] + "-0-bgp0"
        bgp_peer2= ncc_info['cloud_router'] + "-1-bgp1"
        network = ncc_info['ncc_vpc_ext']
        subnetwork = ncc_info['region']+'-'+ncc_info['ncc_vpc_ext']
        ra_bgp_address = ra_ip
        cr_bgp_peer1_addr = ncc_info['cloud_router_ip1']
        cr_bgp_peer2_addr = ncc_info['cloud_router_ip2']
        ra_asn = ncc_info['fortigate_router_asn']
        auth_token = self.bearer_token
        data = {
            "bgp": {
                "asn": ncc_info['cloud_router_asn']
            },
            "bgpPeers": [
                {
                    "routerApplianceInstance": ra,
                    "name": bgp_peer1,
                    "interfaceName": int1,
                    "peerIpAddress": ra_bgp_address,
                    "peerAsn": ra_asn,
                    "ipAddress": cr_bgp_peer1_addr
                },
                {
                    "routerApplianceInstance": ra,
                    "name": bgp_peer2,
                    "interfaceName": int2,
                    "peerIpAddress": ra_bgp_address,
                    "peerAsn": ra_asn,
                    "ipAddress": cr_bgp_peer2_addr
                }
            ],

            "interfaces": [
                {
                    "name": int1,
                    "privateIpAddress": cr_bgp_peer1_addr,
                    "redundantInterface": int2,
                    "subnetwork": "https://www.googleapis.com/compute/beta/projects/" + ncc_info['project'] + "/regions/" + ncc_info['region'] + "/subnetworks/" + subnetwork
                },

                {
                    "name": int2,
                    "privateIpAddress": cr_bgp_peer2_addr,
                    "redundantInterface": int1,
                    "subnetwork": "https://www.googleapis.com/compute/beta/projects/" + ncc_info['project'] + "/regions/" + ncc_info['region'] + "/subnetworks/" + subnetwork
                }
            ],
            "name": ncc_info['cloud_router'],
            "network": "projects/"+ ncc_info['project'] + "/global/networks/" + network,
            "region":  "projects/"+ ncc_info['project'] + "/regions/" + ncc_info['region']

        }
        header = {'Authorization': 'Bearer ' + auth_token}
        response = requests.post(url, json=data, headers=header)
        logger.debug("Successfully created a cloud router: %s", response.json())
        

class GCPStorageClient:
    """Creates a GCP Storage Client."""

    def __init__(self, service_account_file):
        self.service_account_file = service_account_file
        self.storage_client = self._build_storage_client()
        return

    def _build_storage_client(self):
        ''' Create google storage client from the service acccount file '''

        return storage.Client.from_service_account_json(self.service_account_file)


    def read_text_kv_file(self, bucket_name, blob_name):
        ''' Reads content of a key/value text file and converts to a dictionary  '''

        bucket = self.storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        json_data = blob.download_as_string().decode('utf-8').replace(' ','').replace('\n', '').replace('\t','')   
        return json.loads(json_data)



if __name__ == '__main__':
    

    ncc_parser = argparse.ArgumentParser(description='Deploy Fortinet Google NCC solution')

    ncc_parser.add_argument('service_account_file',
                           metavar='service-account-file',
                           type=str,
                           help='service account file to authenticate with google cloud project, e.g. /home/ncc/api-key.json')
    ncc_parser.add_argument('bucket_name',
                           metavar='gcp-bucket-name',
                           type=str,
                           help='google storage bucket name where the input file is stored')
    ncc_parser.add_argument('input_file',
                           metavar='deployment-param-file',
                           type=str,
                           help='name of the source file in the gcp bucket containing parameters needed to complete this deployment')


    # Execute parse_args()
    args = ncc_parser.parse_args()

    service_account_file = args.service_account_file

    if not os.path.exists((service_account_file)):
        logger.error("The path specified does not exist")
        sys.exit()

    bucket_name = args.bucket_name
    input_file = args.input_file

    #Access input txt file in GCP to retrieve required parameters
    try:
        gcp_storage_client = GCPStorageClient(service_account_file)
        ncc_info = gcp_storage_client.read_text_kv_file(bucket_name, input_file)
        logger.info("Reading input file from GCP bucket %s ", bucket_name)
        logger.info("NCC input file: %s", str(ncc_info))
        
    except Exception as e:
        logger.error("Not able to retrieve required input parameters: ", exc_info=True)
        exit(1)
    

    #Create a generic GCP REST client as well as a GCP Compute client
    gcp_rest_client = GCPRestClient(ncc_info, service_account_file)
    print(gcp_rest_client.bearer_token)
    gcp_compute_client = GCPComputeClient(ncc_info, service_account_file)
 
    
    #Create VPCs
    if gcp_compute_client.vpc_exists(ncc_info['ncc_vpc_ext']):
        logger.debug("VPC with the name %s already exists", ncc_info['ncc_vpc_ext'])
    else:
        ncc_vpc_network = gcp_compute_client.create_vpc(ncc_info['ncc_vpc_ext'])
        logger.debug("Creating VPC %s ...", ncc_info['ncc_vpc_ext'])
        gcp_compute_client.wait_for_network_operation(ncc_vpc_network['name'])
        logger.debug("Successfully created VPC %s", ncc_info['ncc_vpc_ext'])
    # create firewall policies for vpc external network
        gcp_compute_client.create_gcp_fw_ingress(ncc_info['ncc_vpc_ext'])
        gcp_compute_client.create_gcp_fw_egress(ncc_info['ncc_vpc_ext'])
    
    if gcp_compute_client.vpc_exists(ncc_info['ncc_vpc_int']):
        logger.debug("VPC with the name %s already exists", ncc_info['ncc_vpc_int'])
    else:
        ncc_vpc_network_internal = gcp_compute_client.create_vpc(ncc_info['ncc_vpc_int'])
        logger.debug("Creating VPC %s ...", ncc_info['ncc_vpc_int'])
        gcp_compute_client.wait_for_network_operation(ncc_vpc_network_internal['name'])
        logger.debug("Successfully created VPC %s", ncc_info['ncc_vpc_int'])


    #Create subnets in both the VPCs
    if gcp_compute_client.subnet_exists(ncc_info['region']+'-'+ncc_info['ncc_vpc_ext']):
        logger.debug("SubNetwork with the name %s already exists", ncc_info['region']+'-'+ncc_info['ncc_vpc_ext'])
    else:
        ncc_vpc_subnets = gcp_compute_client.create_subnets(ncc_info['ncc_vpc_ext'], ncc_info['region']+'-'+ncc_info['ncc_vpc_ext'], ncc_info['ncc_vpc_ext_cidr'])
        logger.debug("Creating subnetwork for VPC %s ...", ncc_info['ncc_vpc_ext'])
        gcp_compute_client.wait_for_subnetwork_operation(ncc_vpc_subnets['name'])
        logger.debug("Successfully created subnetwork for VPC %s", ncc_info['ncc_vpc_ext'])

    if gcp_compute_client.subnet_exists(ncc_info['region']+'-'+ncc_info['ncc_vpc_int']):
        logger.debug("SubNetwork with the name %s already exists", ncc_info['region']+'-'+ncc_info['ncc_vpc_ext'])
    else:
        ncc_vpc_internal_subnets = gcp_compute_client.create_subnets(ncc_info['ncc_vpc_int'], ncc_info['region']+'-'+ncc_info['ncc_vpc_int'], ncc_info['ncc_vpc_int_cidr'])
        logger.debug("Creating subnetwork for VPC %s ...", ncc_info['ncc_vpc_int'])
        gcp_compute_client.wait_for_subnetwork_operation(ncc_vpc_internal_subnets['name'])
        logger.debug("Creating subnetwork for VPC %s", ncc_info['ncc_vpc_int'])
        logger.debug("Successfully created subnetwork for VPC %s", ncc_info['ncc_vpc_int'])

    #ncc_vpc_internal_subnets = create_subnets(ncc_vpc_internal,project, ncc_cidr_internal, NCC_Info['region'])



    # #creating NCC Hub
    gcp_rest_client.create_hub()
    # #Creating Router Appliance
    if gcp_compute_client.instance_exists(ncc_info['fortigate_spoke1']):
        logger.debug("Fortigate Instance with the name %s already exists", ncc_info['fortigate_spoke1'])
        reply = str(input('(Type YES to continue , any other input will exit the program): ')).lower().strip()
        if reply == 'yes': logger.debug("Adding Existing Fortigate instance as a Spoke to %s", ncc_info['ncc_hub'])
        else:
            logger.debug("Exiting !!!")
            exit(1)
    else:
        gcp_compute_client.create_publicip()
        ra_fgt = gcp_compute_client.create_instance(gcp_compute_client.get_publicip('address'))
        gcp_compute_client.wait_for_instance_operation(ra_fgt['name'])


    # #Creating Cloud Router
    spoke_info = gcp_compute_client.get_instance(ncc_info['fortigate_spoke1'])
    logger.debug("Retrived required FortiGate instance spoke info: %s", spoke_info)
    gcp_rest_client.create_cloud_router(spoke_info['ra_ip'], spoke_info['ra_link'])

    # #Registering NVA (FortiGate) GCP NCC hub
    gcp_rest_client.create_spoke(spoke_info['ra_ip'], spoke_info['ra_link'], ncc_info['sitetositeData'])
    logger.info("Deployment of Google NCC and FortiGate NVA have been Completed !")