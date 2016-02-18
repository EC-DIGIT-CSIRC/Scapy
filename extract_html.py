#!/usr/bin/python
#
# Extract HTML from PCAP
# -- use scapy-http to handle http protocol
#    	https://github.com/invernizzi/scapy-http
# 
# Author: David DURVAUX
# Copyright: EC DIGIT CSIRC - December 2015
#
# TODO:
#    - Extended support of other type of content like "text/javascript"
#    - Generic proxy support
#
# Version 0.11
#
#
import base64
import re
import datetime
import glob
import argparse
import os
from struct import *
try:
	from scapy.all import *
	from scapy.layers import http
except:
	print("Oups... something goes wrong while searching for scapy and scapy-http.  Try '# pip install scapy-http'")

def __parse_pcap__(directory, out=None):
	"""
		Parse PCAP to find HTML content

		@TODO - extend function for a more clear and generic behaviour
	"""
	# set binding for proxy
	bind_layers(TCP, http.HTTP, sport=3148)
	bind_layers(TCP, http.HTTP, dport=3148)
	
	for pcap_file in glob("%s/%s" % (directory, "*.pcap")):
		print("Parsing file: %s" % (pcap_file))
		pcap = rdpcap(pcap_file)
		flows = pcap.filter(lambda(s): http.HTTPResponse in s)
	
		html_begin_found = False
		html_end_found = False
		html = ""
		for flow in flows:
			# First layer if HTTP, 2nd layer HTTPResponse, 3rd layer Raw
			payload = flow[http.HTTP].payload

			# search for HTML content
			if not html_begin_found:
				token_re = re.compile(r'Content-Type:\s+text/html', re.IGNORECASE)
				m = token_re.search(str(payload))
				if(m is None):
					continue
				else:
					html_begin_found = True
			else:
				# search for end of HTML content
				token_re = re.compile(r'</html', re.IGNORECASE)
				m = token_re.search(str(payload))
				if(m is not None):
					html_end_found = True
			
			if(html_begin_found):
				# if HTML content, proceed with extraction
				tmp_html = str(payload)
				if(tmp_html is not None):
					# remove crap in front and trailer of the html content
					tmp_html = __extract_html__(tmp_html)
					if(tmp_html is not None):
						html += tmp_html 

			# if HTML content is found, write html to file whenever finish
			if(html_begin_found and html_end_found):
				# reset status flag
				html_end_found = False
				html_begin_found = False

				if(html is not None):
					if(out is None):
						print html #print to console
					else:
						filename = os.path.basename(pcap_file)
						# check that output file doesn't exists
						if(os.path.exists("%s//%s.html" % (out, filename))):
							i = 0
							while(os.path.exists("%s//%s-%s.html" % (out, filename,i))):
								i = i + 1
							filename = "%s-%s" % (filename, i)
						# dump result to file
						fd = open("%s/%s.html" % (out, filename), "wb")
						fd.write(html)
						fd.close()

				#clear buffer
				html = ""
	return

def __extract_html__(payload_str):
	"""
		Cleanup the mess

		-- TEST --
		>>> a = "<HTML>blablabla</HTML></HTML>"
		>>> al = a.lower()
		>>> al
		'<html>blablabla</html></html>'
		>>> al.find("<html>")
		0
		>>> al.find("</html>")
		15
		>>> al[0:15+len("</html>")nalyse Angler from PCAP]
		'<html>blablabla</html>'
	"""
	# where to cut?
	low = -1
	high = -1

	# take a copy of html page in lower char to ease search
	low_p = payload_str.lower()

	# search for beginning of html page
	index = low_p.find("<!doctype html")
	if(index == -1):
		index = low_p.find("<html")
		if(index >= 0):nalyse Angler from PCAP
			low  = index
	else:
		low = index

	# search for end of html page
	index = low_p.find("</html>")
	if(index >= 0):
		high = index + len("</html>")

	# take substring from low to high if they are found
	if(low >= 0 and high >= 0):		
		return payload_str[low:high]
	elif(low >=0):
		return payload_str[low:]
	elif(high >=0):
		return payload_str[:high]
	else:
		return None

def main():
	# Argument definition
	parser = argparse.ArgumentParser(description='Parse PCAP files and search for Angler traces')
	parser.add_argument('-dir', '--directory', help='Directory where to search for PCAP to analyse.')
	parser.add_argument('-out', '--output_directory', help='Directory where to wrote all information extracted (by default stdout)')

	# Start the fun part :)
	args = parser.parse_args()

	# Check if an output directory is set
	directory = None
	if args.output_directory:
		directory = os.path.dirname(args.output_directory)
		if not os.path.exists(directory):
			os.makedirs(directory)

	if args.directory:
		__parse_pcap__(args.directory, directory)
	else:
		print "You need to specify a directory where to search for pcap file"


if __name__ == "__main__":
    main()

# That's all folk ;)