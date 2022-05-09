#!/usr/bin/python3.6
import sys


# format
if len(sys.argv) != 2:
    print ('Format: anade_barra.py file_uri')
    sys.exit()


path_uris_file = sys.argv[1]
pat_out_tmp = "out.txt"

file_out = open(pat_out_tmp, 'a')

try:
	with open(path_uris_file, 'r') as file:
		for line in file:
			if line[0] != "/":
				line = "/" + line
			file_out.write(line)
except IOError:
    print ('File does not exist')

file_out.close()
