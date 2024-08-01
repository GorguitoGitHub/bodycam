import os
import re
import json
import pytz
import base64
import hashlib
import requests
import subprocess
import unicodedata
import functions_framework
from datetime import datetime
from google.auth import default
import google.auth
import google.auth.transport.requests
from googleapiclient.discovery import build


print('---PRENDE---')

LOCAL_ENV                = 'dev'
PROJECT_ID_BODYCAM_REPO  = os.getenv('PROJECT_ID_BODYCAM_REPO', f'vanti-bodycam-sto-repo-{LOCAL_ENV}')
#PROJECT_ID_BODYCAM_TRAN = os.getenv('PROJECT_ID_BODYCAM_TRAN', f'vanti-bodycam-sto-tran-{LOCAL_ENV}')
#LOCATION                = os.getenv('LOCATION', 'us')
BUCKET_ORIGIN_TRAN       = os.getenv('BUCKET_ORIGIN_TRAN', f'vanti-bodycam-sto-tran-{LOCAL_ENV}-tmp-upload-vid-{LOCAL_ENV}')
BUCKET_DESTINATION_REPO  = os.getenv('BUCKET_DESTINATION_REPO', f'vanti-bodycam-sto-repo-{LOCAL_ENV}-def-audit-vid-{LOCAL_ENV}')
SA_GCF_GCS_ENCRIPTION    = os.getenv('GCF_GCS_ENCRIPTION', f'sa-gcf-gcs-bq-services@vanti-bodycam-sto-repo-{LOCAL_ENV}.iam.gserviceaccount.com')
URL_GCF_GCS_ENCRIPTION   = os.getenv('URL_GCF_GCS_ENCRIPTION', f'https://us-central1-vanti-bodycam-sto-repo-{LOCAL_ENV}.cloudfunctions.net/gcf-gcs-encription')


def is_mp4(file_name):
    if file_name.lower().endswith(".mp4"):
        return True
    else:
        return False


def bash_cmd_print(command):
    bash_ls = str(subprocess.check_output(command).decode("utf-8"))
    print(f'{bash_ls}')
    return bash_ls


def del_unidoe_charts(text):
    text_mod = ''.join((c for c in unicodedata.normalize('NFD', text.replace(' ', '_')) if unicodedata.category(c) != 'Mn'))
    text_mod = re.sub(r'[^a-zA-Z0-9._/]|^[^a-zA-Z._]+', '', text_mod).lower()
    return text_mod
    

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
    try:
        objects_list = service.objects().get(**parameters)
        obj_details = objects_list.execute()
        return obj_details
    except Exception as e:
        print(f'ERROR GET OBJECT BUCKET !')
        return False

    
def compare_object(md5h_hash_file_in, details_object_in):
    try:
        if details_object_in :
            if md5h_hash_file_in in details_object_in:
                return True
            else:
                'Sería otra versión'
                return False
        else:
            return False
    except Exception as e:
        print('ERROR COMPARING MD5HASH', e)
    

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


def request_http(filename, path_destination):
    token = get_access_token()
    payload = {
                "action": "encrypt",
                "encryptionFormat": "aes256",
                "serviceAccountImpersonate": f"{SA_GCF_GCS_ENCRIPTION}",
                "smEncryptionKey": f"projects/{PROJECT_ID_BODYCAM_REPO}/secrets/data-int-bodycam-secretkey-01/versions/latest",
                "gsBucketPathOrigin": f"gs://{BUCKET_ORIGIN_TRAN}/{filename}",
                "gsBucketPathDestiny": path_destination
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
    name_folder_year_month = actual_date[:-3]
    

    attributes, data = get_data_attributes(cloudevent) 
    filename = attributes['objectId']
    #bucket_name_in = attributes['bucketId']

    filename_decode = del_unidoe_charts(filename)

    path_destination = f'gs://{BUCKET_DESTINATION_REPO}/{filename_decode}_' + '.enc'

    print(f'--INIT-- :: hello')


    if is_mp4(filename_decode):        
        gcs_file_path = re.sub(f'gs://{BUCKET_DESTINATION_REPO}/', '', filename_decode)
        md5h_hash_file_in = data.get('md5Hash')
        details_object_bucket_destination = gcs_get_object_details(BUCKET_DESTINATION_REPO, gcs_file_path)                
        #list_bucket_out = list_object_bucket(BUCKET_DESTINATION_REPO, 2)
        comparative = compare_object(md5h_hash_file_in, details_object_bucket_destination)
        print(comparative)
        if comparative:
            print('WARNING THE FILE ALREADY EXISTS !')
        else:
            request_http(filename, path_destination)
    else:
        print('THE FILE IS NOT .mp4 FORMAT !')

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
        data = f.read().replace('-prd', f'-{LOCAL_ENV}')
    cloudevent = CloudEvent(json.loads(data))
    trigger_bucket_gcf(cloudevent)