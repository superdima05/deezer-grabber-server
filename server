#!/usr/bin/env python

# Copyright (C) 2019  Deezpy contributors

# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.

# You should have received a copy of the GNU General Public License along
# with this program. If not, see <http://www.gnu.org/licenses/>

# standard libraries:
import hashlib
import os
import re
import platform

# third party libraries:
import mutagen
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from mutagen.easyid3 import EasyID3
from requests.packages.urllib3.util.retry import Retry
from http.server import BaseHTTPRequestHandler, HTTPServer
from transliterate import translit, get_available_language_codes


session = requests.Session()
userAgent = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/68.0.3440.106 Safari/537.36'
    )
httpHeaders = {
        'User-Agent'      : userAgent,
        'Content-Language': 'en-US',
        'Cache-Control'   : 'max-age=0',
        'Accept'          : '*/*',
        'Accept-Charset'  : 'utf-8,ISO-8859-1;q=0.7,*;q=0.3',
        'Accept-Language' : 'en-US;q=0.6,en;q=0.4',
        'Connection'      : 'keep-alive',
        }
session.headers.update(httpHeaders)




def apiCall(method, json_req=False):
    unofficialApiQueries = {
        'api_version': '1.0',
        'api_token'  : 'null' if method == 'deezer.getUserData' else CSRFToken,
        'input'      : '3',
        'method'     : method
        }
    req = requests_retry_session().post(
        url='https://www.deezer.com/ajax/gw-light.php',
        params=unofficialApiQueries,
        json=json_req
        ).json()
    return req['results']


def getTokens():
    req = apiCall('deezer.getUserData')
    global CSRFToken
    CSRFToken = req['checkForm']
    global sidToken
    sidToken = req['SESSION_ID']


def mobileApiCall(method, json_req=False):
    unofficialApiQueries = {
        'api_key' : '4VCYIJUCDLOUELGD1V8WBVYBNVDYOXEWSLLZDONGBBDFVXTZJRXPR29JRLQFO6ZE',
        'sid'     : sidToken,
        'output'  : '3',
        'input'   : '3',
        'method'  : method
        }
    req = requests_retry_session().post(
        url='https://api.deezer.com/1.0/gateway.php',
        params=unofficialApiQueries,
        json=json_req
        ).json()
    return req['results']


def privateApi(songId):
    req = mobileApiCall('song_getData', {'SNG_ID': songId})
    return req


# https://www.peterbe.com/plog/best-practice-with-retries-with-requests
def requests_retry_session(retries=3, backoff_factor=0.3,
                           status_forcelist=(500, 502, 504)):
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        method_whitelist=frozenset(['GET', 'POST'])
    )
    adapter = requests.adapters.HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def getJSON(mediaType, mediaId, subtype=""):
    url = f'https://api.deezer.com/{mediaType}/{mediaId}/{subtype}?limit=-1'
    return requests_retry_session().get(url).json()


def getCoverArt(artID, filename, size):
    url = f'https://e-cdns-images.dzcdn.net/images/cover/{artID}/{size}x{size}.png'
    path = os.path.dirname(filename)
    imageFile = f'{path}/cover.png'
    if not os.path.isdir(path):
        os.makedirs(path)
    if os.path.isfile(imageFile):
        with open(imageFile, 'rb') as f:
            return f.read()
    else:
        with open(imageFile, 'wb') as f:
            r = requests_retry_session().get(url)
            f.write(r.content)
            return r.content


def getLyrics(trackId, filename):
    req = apiCall('song.getLyrics', {'sng_id': trackId})
    if 'LYRICS_SYNC_JSON' in req: # synced lyrics
        rawLyrics = req['LYRICS_SYNC_JSON']
        ext = '.lrc'
        lyrics = []
        for lyricLine in rawLyrics:
            try:
                time = lyricLine['lrc_timestamp']
            except KeyError:
                lyricLine = ''
            else:
                line = lyricLine['line']
                lyricLine = f'{time}{" "}{line}'
            finally:
                lyrics.append(lyricLine + '\n') # TODO add duration?
    elif 'LYRICS_TEXT' in req: # unsynced lyrics
        lyrics = req['LYRICS_TEXT'].splitlines(True) # True keeps the \n
        ext = '.txt'
    else:
        return False
    with open(f'{filename}{ext}', 'a') as f:
        for lyricLine in lyrics:
            f.write(lyricLine)


def getTags(trackInfo, albInfo, playlist):
    try:
        genre = albInfo['genres']['data'][0]['name']
    except:
        genre = ''
    tags = {
        'title'       : trackInfo['title'],
        'discnumber'  : trackInfo['disk_number'],
        'tracknumber' : trackInfo['track_position'],
        'album'       : trackInfo['album']['title'],
        'date'        : trackInfo['album']['release_date'],
        'artist'      : trackInfo['artist']['name'],
        'bpm'         : trackInfo['bpm'],
        'albumartist' : albInfo['artist']['name'],
        'totaltracks' : albInfo['nb_tracks'],
        'label'       : albInfo['label'],
        'genre'       : genre
        }
    return tags


def writeFlacTags(filename, tags, imageUrl):
    try:
        handle = mutagen.File(filename)
    except mutagen.flac.FLACNoHeaderError as error:
        print(error)
        os.remove(filename)
        return False
    handle.delete()
    handle.clear_pictures()
    if imageUrl:
        image = getCoverArt(imageUrl, filename, 1500)
        pic = mutagen.flac.Picture()
        pic.encoding=3
        pic.mime='image/png'
        pic.type=3
        pic.data=image
        handle.add_picture(pic)

    for key, val in tags.items():
        handle[key] = str(val)
    handle.save()
    os.remove('cover.png')
    return True

def getTrackDownloadUrl(privateInfo, quality):
    char = b'\xa4'.decode('unicode_escape')
    step1 = char.join((privateInfo['PUID'],
                      quality, privateInfo['SNG_ID'],
                      privateInfo['MEDIA_VERSION']))
    m = hashlib.md5()
    m.update(bytes([ord(x) for x in step1]))
    step2 = f'{m.hexdigest()}{char}{step1}{char}'
    step2 = step2.ljust(80, ' ')
    cipher = Cipher(algorithms.AES(bytes('jo6aey6haid2Teih', 'ascii')),
                    modes.ECB(), default_backend())
    encryptor = cipher.encryptor()
    step3 = encryptor.update(bytes([ord(x) for x in step2])).hex()
    cdn = privateInfo['PUID'][0]
    decryptedUrl = f'https://e-cdns-proxy-{cdn}.dzcdn.net/mobile/1/{step3}'
    return decryptedUrl


def getBlowfishKey(trackId):
    secret = 'g4el58wc0zvf9na1'
    m = hashlib.md5()
    m.update(bytes([ord(x) for x in trackId]))
    idMd5 = m.hexdigest()
    bfKey = bytes(([(ord(idMd5[i]) ^ ord(idMd5[i+16]) ^ ord(secret[i]))
                  for i in range(16)]))
    return bfKey


def decryptChunk(chunk, bfKey):
    cipher = Cipher(algorithms.Blowfish(bfKey),
                    modes.CBC(bytes([i for i in range(8)])),
                    default_backend())
    decryptor = cipher.decryptor()
    decChunk = decryptor.update(chunk) + decryptor.finalize()
    return decChunk


def downloadTrack(filename, ext, url, bfKey):
    tmpFile = f'{filename}.tmp'
    realFile = f'{filename}{ext}'
    print(f"Downloading: {realFile}... ", end='', flush=True)
    filesize = 0
    i = 0
    req = requests_retry_session().get(url, stream=True)
    if req.headers['Content-length'] == '0':
        print("Empty file, skipping...\n", end='')
        return False
    fileDir = os.path.dirname(realFile)
    if not os.path.isdir(fileDir):
        os.makedirs(fileDir)

    # Decrypt content and write to file
    with open(tmpFile, 'ab') as fd:
        fd.seek(filesize)  # jump to end of the file in order to append to it
        # Only every third 2048 byte block is encrypted.
        for chunk in req.iter_content(2048):
            if i % 3 == 0 and len(chunk) >= 2048:
                chunk = decryptChunk(chunk, bfKey)
            fd.write(chunk)
            i += 1
    os.rename(tmpFile, realFile)
    return True




def getTrack(trackId, playlist=False):
    trackInfo = getJSON('track', trackId)
    albInfo = getJSON('album', trackInfo['album']['id'])
    #if not trackInfo['readable']:
    #    print(f"Song {trackInfo['title']} not available, skipping...")
    #    return False
    privateInfo = privateApi(trackId)
    quality = '9'
    if not quality:
        print((f"Song {trackInfo['title']} not available, skipping..."
               "\nMaybe try with a higher quality setting?"))
        return False, False
    ext = '.flac'

    fullFilenamePath = './'+trackInfo['artist']['name']+" - "+trackInfo['title']+" "+trackInfo['isrc']
    fullFilenamePathExt = f'{fullFilenamePath}{ext}'
    if os.path.isfile(fullFilenamePathExt):
        print(f"{fullFilenamePathExt} already exists!")
        return fullFilenamePathExt, translit(trackInfo['artist']['name']+" - "+trackInfo['title']+" "+trackInfo['isrc']+".flac", "ru", reversed=True)
    else:
        decryptedUrl = getTrackDownloadUrl(privateInfo, quality)
        bfKey = getBlowfishKey(privateInfo['SNG_ID'])
        if downloadTrack(fullFilenamePath, ext, decryptedUrl, bfKey):
            tags = getTags(trackInfo, albInfo, playlist)
            imageUrl = privateInfo['ALB_PICTURE']
            writeFlacTags(fullFilenamePathExt, tags, imageUrl)
            getLyrics(trackId, fullFilenamePath)
        else:
            return False, False
    return fullFilenamePathExt, translit(trackInfo['artist']['name']+" - "+trackInfo['title']+" "+trackInfo['isrc']+".flac", "ru", reversed=True)


def downloadDeezer(url):
	return getTrack(url.split('/')[4])

def init():
    getTokens()


class S(BaseHTTPRequestHandler):
    def _set_response(self, yes=False, name=""):
        self.send_response(200)
        if(yes == False):
        	self.send_header('Content-type', 'application/json')
        else:
        	self.send_header('Content-type', 'audio/vorbis')
        	self.send_header('Content-disposition', 'attachment; filename="'+name.encode("UTF-8").decode()+'"')
        self.end_headers()

    def do_GET(self):
        p = self.path[1:]
        try:
        	r, name = downloadDeezer(p)
        except Exception:
        	r = False
        	name = False
        print(r)
        if(r != False):
        	self._set_response(yes=True, name=name)
        	f = open(r, "rb")
        	self.wfile.write(f.read())
        	f.close()
        	os.remove(r)
        else:
        	self._set_response(yes=False)
        	self.wfile.write(b'{"code": 100, "desc": "error happend"}')

def run(server_class=HTTPServer, handler_class=S, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()

if __name__ == '__main__':
	init()
	run(port=9431)
