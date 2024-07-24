import os
import json
import re
import hashlib
import random
import unicodedata
import gzip
import shutil
from time import sleep
import subprocess
from subprocess import call
from google.cloud import storage, secretmanager
from google.oauth2 import service_account
from google.auth import default, impersonated_credentials
from google.auth.transport.requests import AuthorizedSession
from googleapiclient.discovery import build


import functions_framework


LOCAL_ENV               = 'dev'
LOCATION                = os.getenv('LOCATION', 'us')
PROJECT_ID_BODYCAM_REPO = os.getenv('PROJECT_ID_BODYCAM_REPO', f'vanti-bodycam-sto-repo-{LOCAL_ENV}')
PROJECT_ID_BODYCAM_TRAN = os.getenv('PROJECT_ID_BODYCAM_TRAN', f'vanti-bodycam-sto-tran-{LOCAL_ENV}')
EXTENSION             = {'gzip':'gz'}
ENCRIPTIONS           = ['aes256', 'sha256', 'pgp']


def get_num():
    return random.randint(2, 25) * 3


def bash_cmd_print(command):
    bash_ls = str(subprocess.check_output(command).decode("utf-8"))
    print(f'{bash_ls}')
    return bash_ls


def set_impersonate_sa(email_sa):
    creds, pid = default()
    print(f"Obtained default credentials for the project {pid}")
    tcreds = impersonated_credentials.Credentials(
        source_credentials=creds,
        target_principal=email_sa,
        target_scopes=['https://www.googleapis.com/auth/cloud-platform'],
    )
    return tcreds


def getPost(request):
    param = None
    try:
        param = request.form.to_dict()
        if len(param) == 0:
            raise Exception("no dict")
    except:
        try:
            param = request.json
        except:
            param = {}
    return param


def del_unidoe_charts(text):
    text_mod = ''.join((c for c in unicodedata.normalize('NFD', text.replace(' ', '_')) if unicodedata.category(c) != 'Mn'))
    text_mod = re.sub(r'[^a-zA-Z0-9._]|^[^a-zA-Z._]+', '', text_mod).lower()
    return text_mod


def encrypt_aes(encryption_key, path_file):
    file_name = re.sub(r'^downloaded_', '', path_file)
    path_dest = re.sub(r'^downloaded_', 'encrypted_', path_file)
    cmd = f'openssl enc -aes-256-cbc -salt -in {path_file} -e -pass pass:{file_name} -pbkdf2 -md sha256 -out {path_dest} -k {encryption_key}'
    if call(cmd.split()):
        raise Exception(f"Error while cypher the file: {file_name}")
    return path_dest


def decrypt_aes(encryption_key, path_file):
    filename = path_file.split("/")[-1]
    path_dest = re.sub(r'(^encrypted_)|(^downloaded_)', 'decrypted_', path_file)
    cmd = f'openssl aes-256-cbc -d -in {path_file} -pbkdf2 -out {path_dest} -k {encryption_key}'
    if call(cmd.split()):
        raise Exception("Error while decypher the file: {0}".format(filename))
    return path_dest


def access_secret_version(secret_id, tcredentials):
    name = secret_id
    client = secretmanager.SecretManagerServiceClient(credentials=tcredentials)
    response = client.access_secret_version(name=name)
    secret_payload = response.payload.data.decode("UTF-8")
    return secret_payload


def gcs_get_object_details(bucket_name, gcs_file_path, credentials):
    service = build('storage', 'v1', credentials=credentials)
    parameters = {
        'object': gcs_file_path,
        'bucket': bucket_name,
    }
    objects_list = service.objects().get(**parameters)
    obj_details = objects_list.execute()
    return obj_details



def gcs_download_file(gcs_file_name, project_id, credentials=None):
    local_file_name = gcs_file_name.split('/')[-1]
    bucket_name = gcs_file_name.split('/')[-5]
    gcs_file_path = re.sub(f'gs://{bucket_name}/', '', gcs_file_name)

    obj_details = gcs_get_object_details(bucket_name, gcs_file_path, credentials)

    client = storage.Client(project=project_id, credentials=credentials) if credentials else storage.Client(project=project_id)
    bucket = client.bucket(bucket_name)
    local_file_path = f'downloaded_{del_unidoe_charts(local_file_name)}'
    blob   = bucket.blob(gcs_file_path.replace('%2F', '/'))
    try:
        blob.download_to_filename(f'{local_file_path}')
    except Exception as e:
        print(f'ERROR_DOWNLOAD_GCS: pj:{project_id}, bk:{bucket_name}, fc:{gcs_file_name}, fl:{local_file_name} :: {e}')
        raise e
    bash_cmd_print(["ls", "-lha"])
    print(f'SUCCESS_DOWNLOAD_GCS: pj:{project_id}, bk:{bucket_name}, fc:{gcs_file_name}, fl:{local_file_name}')
    return obj_details, local_file_path


def gcs_upload_file(local_filename, gcs_file_name, project_id, metadata, compress_format, credentials=None):
    client = storage.Client(project=project_id, credentials=credentials) if credentials else storage.Client(project=project_id)
    bucket_name = gcs_file_name.split('/')[2]
    bucket = client.bucket(bucket_name)
    gcs_file_path = re.sub(f'gs://{bucket_name}/', '', gcs_file_name)
    blob = bucket.blob(gcs_file_path)
    #blob.content_encoding = compress_format
    blob.metadata = metadata
    try:
        blob.upload_from_filename(local_filename)
    except Exception as e:
        print(f'ERROR_GCS_UPLOAD: pj:{project_id} bk:{bucket_name} fl:{local_filename} fu:{gcs_file_path}:: {e}')
        raise e
    print(f'SUCCESS_GCS_UPLOAD: pj:{project_id} bk:{bucket_name} fl:{local_filename} fu:{gcs_file_path}')
    return gcs_file_name


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


def get_metadsata_file(local_filename):
    metadata = {}
    try:
        metadata['localBeforeGzMd5Hash'] = calcule_md5(local_filename)
        metadata['localType'] = bash_cmd_print(["file", local_filename]).split(':')[-1].replace('\n','').strip()
        metadata['localExtension'] = local_filename.split('.')[-1]
        metadata['localBeforeGzSize'] = bash_cmd_print(["stat", local_filename]).split('Size:')[1].split()[0]
    except Exception as e:
        print(f'WARNING_get_metadsata_file:: {e}')
    return metadata


def gzip_compress_format(input_file, output_file):
    with open(input_file, 'rb') as f_in:
        with gzip.open(output_file, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    return output_file


def gzip_descompress_format(input_file, output_file):
    with gzip.open(input_file, 'rb') as f_in:
        with open(output_file, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    return output_file


def validate_metadata(metadata, max=8000):
    k = ''.join([str(valor) for valor in metadata.keys()])
    v = ''.join([str(valor) for valor in metadata.values()])
    # prevent maximun limit items
    if len(k+v) > max:
        print(f'WARNIN_validate_metadata:: {metadata}')
        metadata.popitem()
        metadata = validate_metadata(metadata)
    return metadata


def remove_local_files(local_files):
    deleted_files = []
    for i in local_files:
        try:
            if i in deleted_files:
                continue
            call(['rm','-rf', i])
            deleted_files.append(i)
        except Exception as e:
            print(f'WARNING_remove_local_files:: {i}')
    return deleted_files


@functions_framework.http
def trigger_http_gcf(request):
    print(f"TRIGGER_INIT_EVENT:: --- {request} ---")
    post = getPost(request) 
    print(f"TRIGGER_INIT_POST:: --- {post} ---")
    try:
        action = post['action']
        gs_bucket_path_origin = post['gsBucketPathOrigin']
        gs_bucket_path_destiny = post['gsBucketPathDestiny']
        service_account_impersonate = post['serviceAccountImpersonate']
        encryption_format = post['encryptionFormat'].lower() if 'encryptionFormat' in post and post['encryptionFormat'].lower() in ENCRIPTIONS  else None 
        sm_encryption_key = post['smEncryptionKey'] if 'smEncryptionKey' in post else None
        compress_format = post['compressFormat'].lower() if 'compressFormat' in post and post['compressFormat'].lower() in list(EXTENSION.keys()) else None
    except Exception as e:
        print(f'ERROR_trigger_gcf_http:: {e}')
        return ''
    
    file_to_action = ''
    actioned_file = ''

    # Get Impersonate authentication
    tcredentials = set_impersonate_sa(service_account_impersonate)
    
    # Get secret key
    encryption_key = access_secret_version(sm_encryption_key, tcredentials)
    
    # Download form GCS
    obj_details, downloaded_file = gcs_download_file(gs_bucket_path_origin, PROJECT_ID_BODYCAM_TRAN, tcredentials)
    print(obj_details)

    # Get metadata local file
    metadata = get_metadsata_file(downloaded_file)
    metadata = metadata | obj_details['metadata'] if 'metadata' in obj_details else metadata
    metadata['encryptionFormat'] = encryption_format
    metadata['smEncryptedKey'] = sm_encryption_key if action == 'encrypt' else None
    metadata['smDencrypedKey'] = sm_encryption_key if action == 'decrypt' else None
    metadata['gcsOriginFile'] = obj_details['id']
    metadata['gcsOriginMd5Hash'] = obj_details['md5Hash']
    metadata['gcsOriginCrc32c'] = obj_details['crc32c']
    metadata['gcsOriginCreatedTime'] = obj_details['timeCreated']
    metadata['gcsOriginGeneration'] = obj_details['generation']
 
    # Compress file (before encrypt)
    if compress_format and action == "encrypt":
        file_to_action = gzip_compress_format(downloaded_file, f'{downloaded_file}.{EXTENSION[compress_format]}')
    else:
        file_to_action = downloaded_file

    # Encrypte file
    if action == 'encrypt':
        if encryption_format == 'aes256':
            actioned_file = encrypt_aes(encryption_key=encryption_key, path_file=file_to_action)
    elif action == 'decrypt':
        file_to_action = compress_format if compress_format else downloaded_file
        if encryption_format == 'aes256':
            actioned_file = decrypt_aes(encryption_key=encryption_key, path_file=file_to_action)
    else:
        return 'no_action'
    
    # Decrypt file (after decrypt FAIL WHEN GZIP)
    if compress_format and action == "decrypt":
        actioned_file = gzip_descompress_format(actioned_file, f'unzip_{downloaded_file}')
    else:
        actioned_file = actioned_file

    # validate max number characteres
    metadata = validate_metadata(metadata)
    # Load GCS file
    uploaded_file = gcs_upload_file(actioned_file, gs_bucket_path_destiny, PROJECT_ID_BODYCAM_REPO, metadata, compress_format, tcredentials)
    returne = {'uploadedFile':uploaded_file, 'metadata':metadata}

    # remove localfiles
    remove_local_files([downloaded_file, file_to_action, actioned_file])

    print(f'INFO_FINISH::{returne}')
    return returne


# Only for local run
if __name__ == "__main__":
    import json
    # Dummy Envent Class
    class CloudEvent(dict):
        def __init__(self, data):
            self.json = data
        def __iter__(self):
            return iter(self.data)
    # Load example json file
    with open(f'./src/test_logs/request_post_enc_{LOCAL_ENV}.json') as f:
        data = f.read().replace('-prd', f'-{LOCAL_ENV}')
    cloudevent = CloudEvent(json.loads(data))
    # Trigger main function
    trigger_http_gcf(cloudevent)
