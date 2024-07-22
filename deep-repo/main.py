import os
import re
import json
import pytz
import base64
import hashlib
import requests
import subprocess
import functions_framework
from datetime import datetime
from google.auth import default
import google.auth
import google.auth.transport.requests
#from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build


print('---PRENDE---')

LOCAL_ENV               = 'dev'
PROJECT_ID_BODYCAM_REPO = os.getenv('PROJECT_ID_BODYCAM_REPO', f'vanti-bodycam-sto-repo-{LOCAL_ENV}')
PROJECT_ID_BODYCAM_TRAN = os.getenv('PROJECT_ID_BODYCAM_TRAN', f'vanti-bodycam-sto-tran-{LOCAL_ENV}')
LOCATION                = os.getenv('LOCATION', 'us')
BUCKET_DESTINATION      = os.getenv('BUCKET_DESTINATION', 'vanti-bodycam-sto-repo-dev-def-audit-vid-dev')
URL_GCF_GCS_ENCRIPTION  = os.getenv('URL_gcf-gcs-encription', 'https://us-central1-vanti-bodycam-sto-repo-dev.cloudfunctions.net/gcf-gcs-encription')
GCF_GCS_ENCRIPTION      = os.getenv('GCF_GCS_ENCRIPTION', 'sa-gcf-gcs-bq-services@vanti-bodycam-sto-repo-dev.iam.gserviceaccount.com')


def is_mp4(file_name):
    if file_name.lower().endswith(".mp4"):
        return True
    else:
        return False


def bash_cmd_print(command):
    bash_ls = str(subprocess.check_output(command).decode("utf-8"))
    print(f'{bash_ls}')
    return bash_ls
    

def get_data_attributes(cloud_event):
    attributes = {}
    data = {}
    try:
        if "message" in cloud_event.data:
            attributes = cloud_event.data['message']['attributes']
        else:
            attributes = cloud_event.attributes
    except Exception as e:
        print(f'WARNNING_GET_ATTRIBUTES_PUBSUB: {e}')

    try:
        if "message" in cloud_event.data:
            data = base64.b64decode(cloud_event.data["message"]["data"]).decode('utf-8').replace('\'', '"')
            data = json.loads(data) if data != "" else {}
        else: 
            data = cloud_event.data
    except Exception as e:
        print(f'WARNNING_GET_DATA_PUBSUB: {e}')
    
    return attributes, data


def calcule_md5(local_filename):
    md5_str = ''
    try:
        md5 = hashlib.md5()
        with open(local_filename, "rb") as file:
            while chunk := file.read(4096):
                md5.update(chunk)
        md5_str = md5.hexdigest()
    except Exception as e:
        md5_str = bash_cmd_print(["md5sum", local_filename]).split()[0] 
    return md5_str


def gcs_get_object_details(bucket_name, gcs_file_path):
    service = build('storage', 'v1')
    parameters = {
        'object': gcs_file_path,
        'bucket': bucket_name,
    }
    objects_list = service.objects().get(**parameters)
    obj_details = objects_list.execute()
    #print('Response object:', obj_details)
    return obj_details


def list_object_bucket(bucket_to_list):
    list_md5_hash_objects_bucket_repo = []
    next_page_token = ''
    flag = True
    try:
        while flag:
            flag = False
            service = build('storage', 'v1')
            parameters ={    
                'bucket' : bucket_to_list,
                #'delimiter' : '',
                #'endOffset' : '',        
                'includeFoldersAsPrefixes' : False,
                'includeTrailingDelimiter' : False,
                #'matchGlob' : '',
                'maxResults' : 2,
                'pageToken' : next_page_token,
                #'prefix' : '',
                'projection' : 'full',
                'softDeleted' : False,
                #'startOffset' : '',
                #'userProject' : '',
                'versions' : False
            }
            response = service.objects().list(**parameters)
            response = response.execute()
            #print('Response bucket:', response)

            for object in response['items']:
                #print(object['md5Hash'])
                list_md5_hash_objects_bucket_repo.append(object['md5Hash'])
                #list_md5_hash_objects_bucket_repo.append(object.get('md5Hash'))

            if response.get('nextPageToken'):
                flag = True
                next_page_token = response.get('nextPageToken')

        print(list_md5_hash_objects_bucket_repo)
        return list_md5_hash_objects_bucket_repo
    
    except Exception as e:
        print('EXECUTE ERROR OBTAIN OBJECTS LIST', e)


def compare_list(md5h_hash_file_in, list_bucket_out):
    try:
        if iter(list_bucket_out):
            if md5h_hash_file_in in list_bucket_out:
                return True
            else:
                return False
    except Exception as e:
        print('ERROR INTO LIST OBJECTS', e)
    

def get_access_token():
    try:
        metadata_server_url = 'http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience='
        token_full_url = metadata_server_url + URL_GCF_GCS_ENCRIPTION
        token_headers = {'Metadata-Flavor': 'Google'}
        token_response = requests.get(token_full_url, headers=token_headers)
        jwt = token_response.text
        print(f'INFO_TK:: {jwt} -- ')
        return jwt
    except Exception as e:
        print(f'WARNING_TK:: {e} -- ')


def request_http(filename):
    token = get_access_token()
    payload = {
                "action": "encrypt",
                "encryptionFormat": "aes256",
                "serviceAccountImpersonate": f"{GCF_GCS_ENCRIPTION}",
                "smEncryptionKey": f"projects/{PROJECT_ID_BODYCAM_REPO}/secrets/data-int-bodycam-secretkey-01/versions/latest",
                "gsBucketPathOrigin": f"gs://{PROJECT_ID_BODYCAM_TRAN}/vanti-bodycam-sto-tran-dev-tmp-upload-vid-dev/{filename}",
                "gsBucketPathDestiny": f"gs://{PROJECT_ID_BODYCAM_REPO}/vanti-bodycam-sto-repo-dev-def-audit-vid-dev/{filename}.enc"
                }  
    headers = {'Authorization': f'Bearer {token}',
               'Content-Type': 'application/json'
                }        
    post_response = requests.post(URL_GCF_GCS_ENCRIPTION, headers=headers, data=json.dumps(payload))
    if post_response.status_code != 200:
        error = f'ERROR_HTTP_REQUEST:: code: {post_response.status_code}, reaseon: {post_response.reason}, headers:{str(post_response.headers)}'
        print(error)
        #raise error
    #return post_response.json()


@functions_framework.cloud_event
def trigger_bucket_gcf(cloudevent):
    print(f"TRIGGER_INIT_EVENT:: --- {cloudevent} ---")
    colombia_time_zone = pytz.timezone('America/Bogota')
    date_time = datetime.now(colombia_time_zone)
    actual_date = str(date_time.date()).replace('-','.')
    name_folder = actual_date[:-3]
    #path_destination = 'dataqualityscans/' + f'{name_folder}/' + name_scan + '_' + actual_date + '.json'
    attributes, data = get_data_attributes(cloudevent) 

    print(f'--INIT-- :: hello')

    filename = attributes['objectId']
    bucket_name_in = attributes['bucketId']

    if is_mp4(filename):
        gcs_file_path = re.sub(f'gs://{bucket_name_in}/', '', filename)
        details_object_in = gcs_get_object_details(bucket_name_in, gcs_file_path)        
        md5h_hash_file_in = details_object_in.get('md5Hash')
        #md5h_hash_file_in = details_object_in.get('md5Hash')
        #print(md5h_hash_file_in)
        #print(type(details_object_in))
        list_bucket_out = list_object_bucket(BUCKET_DESTINATION)
        comparative = compare_list(md5h_hash_file_in, list_bucket_out)
        print(comparative)
        if comparative:
            print('WARNING THE FILE ALREADY EXISTS !')
        else:
            request_http(filename)
    else:
        print('THE FILE IS NOT mp4 FORMAT !')

    return 'ok'


# Only for local run
if __name__ == "__main__":
    import json
    # Dummy Envent Class
    class CloudEvent(dict):
        def __init__(self, data):
            self['source']  = {'data_access': {}}
            self['data']    = data
            self.data       = data['data'] if 'data' in data else data
            self.attributes = data['attributes'] if 'attributes' in data else {}
        def __iter__(self):
            return iter(self.data)
    
    with open('/Asignaciones/Proyecto_bodycam_25_abril_2024/ba-bodycam-services/src/test_logs/request_cloudEvent.json') as f:
        data = f.read()
    with open('/Asignaciones/Proyecto_bodycam_25_abril_2024/ba-bodycam-services/src/test_logs/request_detail_object.json') as f:
        details_object_in = f.read()
        details_object_in = json.loads(details_object_in)
    with open('/Asignaciones/Proyecto_bodycam_25_abril_2024/ba-bodycam-services/src/test_logs/request_list_objects_bucket.json') as f:
        delist_bucket_out = f.read()
        delist_bucket_out = json.loads(delist_bucket_out)
    cloudevent = CloudEvent(json.loads(data))
    trigger_bucket_gcf(cloudevent)