import os
import json
import pytz
import base64
import pandas as pd
from google.cloud import bigquery
from datetime import datetime, timedelta

import functions_framework


LOCAL_ENV               = 'dev'
#PROJECT_ID_BODYCAM_REPO = os.getenv('PROJECT_ID_BODYCAM_REPO', f'vanti-bodycam-sto-repo-{LOCAL_ENV}')
#BUCKET_REPO  = os.getenv('BUCKET_DESTINATION_REPO', f'vanti-bodycam-sto-repo-{LOCAL_ENV}-def-audit-vid-{LOCAL_ENV}')
#PROJECT_ID_DATALAKE     = os.getenv('PROJECT_ID_DATALAKE', f'vanti-data-sto-{LOCAL_ENV}')
#LOCATION                = os.getenv('LOCATION', 'us')
PATH_TABLE_BIGQUERY     = os.getenv('PATH_TABLE_BIGQUERY',f'vanti-data-sto-{LOCAL_ENV}.del_bodycam.videos_history')


print('---PRENDE---')


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


def convert_timestamp_utc_to_localtimestamp(timestamp_utc, localzone = 'America/Bogota'):
    colombia_time_zone = pytz.timezone(localzone)
    time_utc_datetime_format = datetime.fromisoformat(timestamp_utc)
    local_time = time_utc_datetime_format.astimezone(colombia_time_zone)
    return local_time


def upload_video_history_to_bq(table_id, video_name, uploaded_date, creation_date, supervisor_name, metadata, delete_prog, version_history):
    client_bigquery = bigquery.client()
    data = [video_name, uploaded_date, creation_date, supervisor_name, metadata, delete_prog, version_history]
    columns_table = ['video_name', 'uploaded_date', 'creation_date', 'supervisor_name', 'metadata', 'delete_prog', 'version_history']
    dataframe = pd.DataFrame(data, columns= columns_table)
    job = client_bigquery.load_table_from_dataframe(dataframe, table_id)
    job.result()

    table = client_bigquery.get_table(table_id)

    print(f'Load {table.num_rows} rows {len(table.schema)} and colun to {table_id} ')


@functions_framework.cloud_event
def trigger_bucket_gcf(cloudevent):    
    print(f"TRIGGER_INIT_EVENT:: --- {cloudevent} ---")

    attributes, data = get_data_attributes(cloudevent) 
    path_folder_file = attributes['objectId']
    bucket_name = attributes['bucketId']
    load_time = attributes['eventTime']
    metadata = data['metadata']
 
    
    print(f'--INIT-- :: hello')


    path_origin = f'gs://{bucket_name}/{path_folder_file}'
    local_load_time = convert_timestamp_utc_to_localtimestamp(load_time)
    date_delete = local_load_time.date() + timedelta(days=30)

    upload_video_history_to_bq(path_origin, local_load_time, 'creation_dATE', 'SUPERV_name', metadata, date_delete, 'version_1')

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
    # Load example json file
    with open('./src/test_logs/request_bigquery_event.json') as f:
        table = 'vbrk'
        data = f.read().replace('-prd', f'-{LOCAL_ENV}').replace('.ever', f'.{table}').replace('.contrato','.{table}').replace('/ever','/{table}')
    cloudevent = CloudEvent(json.loads(data))
    trigger_bucket_gcf(cloudevent)
