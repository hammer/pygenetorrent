#! /usr/bin/env python
import argparse
import hashlib
import logging
import os
import random
import string
import tempfile

import bencode
from Crypto.PublicKey import RSA
import pkiutils
import requests


FINGERPRINT_PREFIX = '-GT3850-'
GT_CERT_SIGN_TAIL = 'gtsession'
RSA_KEY_SIZE = 1024
RSA_EXPONENT = 65537 # RSA_F4
DISTINGUISHED_NAME = {
    'c': 'US',
    'st': 'CA',
    'l': 'San Jose',
    'o': 'ploaders, Inc',
    'ou': 'staff',
    'cn': 'www.uploadersinc.com',
    'emailaddress': 'root@uploadersinc.com',
}

def get_auth_token(credential_file):
    # TODO(hammer): handle URLs and files
    r = requests.get(credential_file)
    auth_token = r.content
    return auth_token

def get_gto_dict(content_specifier, auth_token):
    # TODO(hammer): handle non-URIs
    payload = {'token': auth_token}
    r = requests.post(content_specifier, data=payload)
    gto_dict = bencode.bdecode(r.content)
    return gto_dict

def get_cert_sign_url(content_specifier):
    # TODO(hammer): handle exceptions
    url_marker = '/cghub/data/'
    return content_specifier.split(url_marker)[0] + url_marker + GT_CERT_SIGN_TAIL

def get_info_hash(gto_dict):
    return hashlib.sha1(bencode.bencode(gto_dict.get('info'))).hexdigest()

def get_crt(cert_sign_url, auth_token, csr, info_hash):
    payload = {
        'token': auth_token,
        'cert_req': csr,
        'info_hash': info_hash,
    }
    r = requests.post(cert_sign_url, data=payload)
    return r.content

def get_random_string(n):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(n))

def get_fingerprint():
    suffix = get_random_string(12)
    return FINGERPRINT_PREFIX + suffix

def get_temp_crt_file_path(crt):
    temp_crt_file_fd, temp_crt_file_path = tempfile.mkstemp('.crt')
    temp_crt_file = os.fdopen(temp_crt_file_fd, 'w')
    temp_crt_file.write(crt)
    temp_crt_file.close()
    logging.debug('Wrote %s' % temp_crt_file_path)
    return temp_crt_file_path

def get_temp_key_file_path(rsa):
    temp_key_file_fd, temp_key_file_path = tempfile.mkstemp('.key')
    temp_key_file = os.fdopen(temp_key_file_fd, 'w')
    key = rsa.exportKey('DER', pkcs=8).encode('base64').strip()
    chunk_key = [key[i:i + 64] for i in xrange(0, len(key), 64)]
    temp_key_file.write('-----BEGIN PRIVATE KEY-----\n')
    temp_key_file.writelines(chunk_key)
    temp_key_file.write('\n-----END PRIVATE KEY-----\n')
    temp_key_file.close()
    logging.debug('Wrote %s' % temp_key_file_path)
    return temp_key_file_path

def make_tracker_request(gto_dict, info_hash, rsa, crt):
    # TODO(hammer): support partial downloads
    peer_id = get_fingerprint()
    left = sum([f.get('length') for f in gto_dict.get('info').get('files')])
    key = get_random_string(8)
    payload = {
        'info_hash': info_hash,
        'peer_id': peer_id,
        'port': 20893,
        'uploaded': 0,
        'downloaded': 0,
        'left': left,
        'corrupt': 0,
        'redundant': 0,
        'compact': 1,
        'numwant': 200,
        'key': key,
        'no_peer_id': 1,
        'supportcrypto': 1,
        'event': 'started',
    }
    url_base = 'https://dream.annailabs.com:21111/tracker.php/announce'
    temp_crt_file_path = get_temp_crt_file_path(crt)
    temp_key_file_path = get_temp_key_file_path(rsa)
    r = requests.get(url_base, params=payload, verify=False,
                     cert=(temp_crt_file_path, temp_key_file_path))
    logging.debug('Tracker response content: %s' % r.content)
    os.remove(temp_crt_file_path)
    os.remove(temp_key_file_path)
    tracker_response = bencode.bdecode(r.content.strip())
    return tracker_response


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--credential-file', dest='credential_file', required=True)
    parser.add_argument('-d', dest='content_specifiers', nargs='+', required=True)
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()
    if args.verbose: logging.basicConfig(level=logging.DEBUG)
    logging.debug('Parsed argument credential_file: %s' % args.credential_file)
    logging.debug('Parsed argument content_specifiers: %s' % args.content_specifiers)

    auth_token = get_auth_token(args.credential_file)
    logging.debug('Got auth_token: %s' % auth_token)

    for content_specifier in args.content_specifiers:
        # Get torrent information
        gto_dict = get_gto_dict(content_specifier, auth_token)
        logging.debug('Got gto_dict: %s' % gto_dict.get('info').get('name'))

        # Authenticate
        cert_sign_url = get_cert_sign_url(content_specifier)
        logging.debug('Got cert_sign_url: %s' % cert_sign_url)
        info_hash = get_info_hash(gto_dict)
        logging.debug('Got info_hash: %s' % info_hash)
        rsa = RSA.generate(bits=RSA_KEY_SIZE, e=RSA_EXPONENT)
        logging.debug('RSA keypair generated; public key: %s' % rsa.publickey().exportKey())
        csr = pkiutils.create_csr(rsa, DISTINGUISHED_NAME)
        logging.debug('CSR generated: %s' % csr)
        crt = get_crt(cert_sign_url, auth_token, csr, info_hash)
        logging.debug('Got signed CRT: %s' % crt)

        # TODO(hammer): Download
        tracker_response = make_tracker_request(gto_dict, info_hash, rsa, crt)
        logging.debug('Got tracker response: %s' % tracker_response)
