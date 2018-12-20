#!/usr/bin/env python3
import argparse
import glob
import hashlib
import io
import json
import os
import pathlib
import signal
import subprocess

import requests
import sys
import time
from getpass import getpass

import boto3
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from boto3.dynamodb.conditions import Key
from hachoir.core import config as HachoirConfig
from hachoir.metadata import extractMetadata
from hachoir.parser import createParser
from PIL import Image

HachoirConfig.quiet = True
home = str(pathlib.Path.home())
rsa_pub = os.path.join(home, ".ssh", "id_rsa.pub")
rsa_pri = os.path.join(home, ".ssh", "id_rsa")

glacier = boto3.client('glacier')
s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
kyoto_server = None


def thumbnail(sha256, media, metadata, size=(128, 128)):
    mime = metadata['MIME type'].split('/')[0]
    with io.BytesIO() as tb:
        if mime == "image":
            im = Image.open(media)
            im.thumbnail(size)
            im.save(tb, "JPEG")
        elif mime == "video":
            cmd = "ffmpeg -i %s -ss 00:00:05 -vframes 1 -filter:v scale='%s:-1' -f singlejpeg -" % (media, size[0])
            print(cmd)
            ffmpeg = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE)
            tb.write(ffmpeg.stdout.read())
        else:
            print("/!\ Warning thumbnail unavailable for media %s" % media)
        tb.seek(0)
        requests.put("http://localhost:1978/%s" % sha256, data=tb.read())


def init(vault):
    init_ktserver(vault)
    init_dynamodb(vault)
    if vault not in glacier.list_vaults():
        glacier.create_vault(vaultName=vault)


def init_dynamodb(vault):
    dynamodb_client = boto3.client('dynamodb')
    existing_tables = dynamodb_client.list_tables()['TableNames']
    if vault not in existing_tables:
        table = dynamodb_client.create_table(
            TableName=vault,
            KeySchema=[{'AttributeName': 'sha256', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'sha256', 'AttributeType': 'S'}],
            ProvisionedThroughput={'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}
        )
        print("Table status:", table.table_status)


def init_ktserver(vault):
    response = s3.list_buckets()
    buckets = [bucket['Name'] for bucket in response['Buckets']]
    if "rupes" not in buckets:
        s3.create_bucket(Bucket='rupes')
    dbs = key['Key']
    for key in s3.list_objects(Bucket='rupes')['Contents']:
        if vault in dbs:
            s3.Bucket('rupes').download_file(vault, vault)
            decrypt(vault, vault + ".kch", rsa_pri)
    kyoto_server = subprocess.Popen(["ktserver", vault + ".kch"], stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)


def save():
    os.killpg(os.getpgid(kyoto_server.pid), signal.SIGTERM)


def sha256sum(filename):
    h = hashlib.sha256()
    b = bytearray(128 * 1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        for n in iter(lambda: f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()


def sizeof_fmt(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


def encrypt(ifile, out_file, rsa_pub):
    recipient_key = RSA.importKey(open(rsa_pub).read())
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    out_file.write(cipher_rsa.encrypt(session_key))
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(ifile.read())
    out_file.write(cipher_aes.nonce)
    out_file.write(tag)
    out_file.write(ciphertext)


def decrypt(ifile, filepath, rsa_pri):
    private_key = RSA.import_key(open(rsa_pri).read(), passphrase=getpass(prompt='RSA private key passphrase: '))
    enc_session_key, nonce, tag, ciphertext = [ifile.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    with open(filepath, 'wb') as o:
        o.write(data)


def inventory(vaultName='photos'):
    job_req = glacier.initiate_job(vaultName=vaultName, jobParameters={'Type': 'inventory-retrieval'})
    while True:
        status = glacier.describe_job(vaultName=vaultName, jobId=job_req['jobId'])
        if status['Completed']:
            break
        print("Wait inventory")
        time.sleep(300)

    job_resp = glacier.get_job_output(vaultName=vaultName, jobId=job_req['jobId'])
    output = job_resp['body'].read()  # first download the output and then parse the JSON
    archive_list = json.loads(output)['ArchiveList']
    return archive_list


def find(dir):
    unknown_ext = set()
    for filename in glob.iglob(dir + '**/*', recursive=True):
        ext = filename.split('.')[-1].lower()
        if ext in ['jpg', 'png', 'mp4']:
            yield filename
        elif ext not in unknown_ext:
            unknown_ext.add(ext)
            print("/!\ Extension -%s- not recognized" % ext)


def metadata(media):
    parser = createParser(media)
    if not parser:
        print("Unable to parse file %s" % media, file=stderr)
        return
    with parser:
        try:
            return extractMetadata(parser).exportDictionary()['Metadata']
        except Exception as err:
            print("Metadata extraction error: %s" % err)
            return


def upload(media, vault_name):
    encfile = io.BytesIO()
    with open(media, 'rb') as ifile:
        encrypt(ifile, encfile, rsa_pub)
    encfile.seek(0)
    m = metadata(media)
    if not m or not 'Creation date' in m.keys():
        print("/!\ Cannot extract metadata (Creation date) upload canceled")
        print(m)
        return
    sha_sum = sha256sum(media)
    table = dynamodb.Table(vault_name)
    response = table.query(
        KeyConditionExpression=Key('sha256').eq(sha_sum)
    )
    if len(response['Items']) == 0:
        d = "%s %s %s" % (sha_sum, m['Creation date'], os.path.basename(media))
        response = glacier.upload_archive(vaultName=vault_name, archiveDescription=d, body=encfile)
        if 300 > response["ResponseMetadata"]["HTTPStatusCode"] >= 200:
            table.put_item(Item={'sha256': sha_sum,
                                 'filename': os.path.basename(media),
                                 'archiveId': response['archiveId'],
                                 'metadata': m})
    else:
        print("Already in Glacier %s" % media)


def main(args):
    init(args.vault)
    mediafiles = list(find(args.input_dir))
    upload_size = sum([os.path.getsize(media) for media in mediafiles])
    if input("%s of data to upload, are ready ? [y/n]" % sizeof_fmt(upload_size)) == "y":
        current_size = 0
        for media in mediafiles:
            upload(media, args.vault)
            perc = 100.0 * current_size / upload_size
            current_size += os.path.getsize(media)
            print("%02d%% - Upload %s - %s" % (perc, media, sizeof_fmt(os.path.getsize(media))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--sync", action="store_true", help='Sync archive list')
    parser.add_argument("-v", "--vault", nargs='?', default="photos", help='vault name (default photos)')
    parser.add_argument("input_dir", help="directory to upload")
    args = parser.parse_args()
    if args.sync:
        archive_list = inventory()
        with("archive_list.json", 'w') as al:
            json.dump(archive_list, al)
        # FIXME sync with dynamodb
    else:
        main(args)
