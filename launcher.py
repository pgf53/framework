#!/usr/bin/python3.6
import sys
import re
import requests
import time
import os
import urllib.parse

ip_server = sys.argv[1]
uri = sys.argv[2]
uri_encoded = urllib.parse.quote(uri)	#codificamos la uri para evitar problemas en el envío.
launch_uri = ip_server + uri_encoded
req = requests.get(launch_uri)	#realizamos el lanzamiento de la uri codificada.

