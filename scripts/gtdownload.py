#! /usr/bin/env python3
import argparse
import base64
import hashlib
import logging
import os
import random
import socket
import ssl
import string
import struct
import tempfile
import urllib

import bcoding as bencode
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
    return hashlib.sha1(bencode.bencode(gto_dict.get('info')))

def get_crt(cert_sign_url, auth_token, csr, info_hash):
    payload = {
        'token': auth_token,
        'cert_req': csr,
        'info_hash': info_hash.hexdigest(),
    }
    r = requests.post(cert_sign_url, data=payload)
    return r.content

def get_random_string(n):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(n))

def get_fingerprint():
    suffix = get_random_string(12)
    return FINGERPRINT_PREFIX + suffix

def get_temp_crt_file(crt):
    temp_crt_file_fd, temp_crt_file_path = tempfile.mkstemp('.crt')
    temp_crt_file = os.fdopen(temp_crt_file_fd, 'w')
    temp_crt_file.write(crt.decode())
    temp_crt_file.close()
    logging.debug('Wrote %s' % temp_crt_file_path)
    return temp_crt_file_path

def get_temp_key_file(rsa):
    temp_key_file_fd, temp_key_file_path = tempfile.mkstemp('.key')
    temp_key_file = os.fdopen(temp_key_file_fd, 'w')
    key = base64.encodestring(rsa.exportKey('DER', pkcs=8)).decode()
    chunk_key = [key[i:i + 64] for i in range(0, len(key), 64)]
    temp_key_file.write('-----BEGIN PRIVATE KEY-----\n')
    temp_key_file.writelines(chunk_key)
    temp_key_file.write('-----END PRIVATE KEY-----\n')
    temp_key_file.close()
    logging.debug('Wrote %s' % temp_key_file_path)
    return temp_key_file_path

def make_tracker_request(gto_dict, peer_id, info_hash, key_file, crt_file):
    # TODO(hammer): support partial downloads
    left = sum([f.get('length') for f in gto_dict.get('info').get('files')])
    key = get_random_string(8)
    payload = {
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
    url = 'https://dream.annailabs.com:21111/tracker.php/announce'
    url += '?info_hash=' + urllib.parse.quote(info_hash.digest(), '') + '&'
    url += urllib.parse.urlencode(payload)
    r = requests.get(url, verify=False, cert=(crt_file, key_file))
    logging.debug('Tracker response content: %s' % r.content)
    tracker_response = bencode.bdecode(r.content.strip())
    return tracker_response

def get_peer_ip_and_port(six_bytes):
    ip = '.'.join([str(byte) for byte in six_bytes[:4]])
    port = (six_bytes[4] << 8) + six_bytes[5]
    return ip, port

def validate_handshake(handshake_response):
    # TODO(hammer): examine reserved to determine extensions supported
    pstrlen = handshake_response[0]
    pstr = handshake_response[1:pstrlen + 1]
    reserved, info_hash, peer_id = struct.unpack('8s20s20s', handshake_response[pstrlen+1:])
    logging.debug('Handshake response contents: %s' % locals())

def handshake_with_peer(peer_ip, peer_port, key_file, crt_file, info_hash, peer_id):
    pstr = 'BitTorrent protocol'
    pstrlen = len(pstr)

    handshake = b''.join([
        chr(pstrlen).encode(),
        pstr.encode(),
        (chr(0) * 8).encode(),
        info_hash.digest(),
        peer_id.encode(),
    ])
    logging.debug('Handshake length: %d' % len(handshake))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = ssl.SSLSocket(sock, keyfile=key_file, certfile=crt_file,
                         ssl_version=ssl.PROTOCOL_TLSv1,
                         server_hostname=info_hash.hexdigest())
    sock.connect((peer_ip, peer_port))
    sock.send(handshake)
    handshake_response = sock.recv(68)
    logging.debug('Handshake response: %s' % handshake_response)
    validate_handshake(handshake_response)
    return sock


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
        logging.debug('Got info_hash (in hex): %s' % info_hash.hexdigest())
        rsa = RSA.generate(bits=RSA_KEY_SIZE, e=RSA_EXPONENT)
        logging.debug('RSA keypair generated; public key: %s' % rsa.publickey().exportKey())
        csr = pkiutils.create_csr(rsa, DISTINGUISHED_NAME)
        logging.debug('CSR generated: %s' % csr)
        crt = get_crt(cert_sign_url, auth_token, csr, info_hash)
        logging.debug('Got signed CRT: %s' % crt)
        temp_key_file = get_temp_key_file(rsa)
        temp_crt_file = get_temp_crt_file(crt)

        # Download
        peer_id = get_fingerprint()
        logging.debug('Got peer id: %s' % peer_id)
        tracker_response = make_tracker_request(gto_dict, peer_id, info_hash,
                                                temp_key_file, temp_crt_file)
        logging.debug('Got tracker response: %s' % tracker_response)
        peer_ip, peer_port = get_peer_ip_and_port(tracker_response.get('peers'))
        logging.debug('Got peer ip and port: %s:%s' % (peer_ip, peer_port))
        sock = handshake_with_peer(peer_ip, peer_port,
                                   temp_key_file, temp_crt_file,
                                   info_hash, peer_id)

        # Clean up
        os.remove(temp_key_file)
        os.remove(temp_crt_file)

