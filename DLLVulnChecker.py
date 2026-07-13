#!/usr/bin/env python3

import requests
import re
import time
from datetime import datetime
import sys, signal
import os

# Vulnerability class

class Vulnerability:
	def __init__(self, name="", severity="", component="", versions="", download="", publication_date=""):
		self._name = name
		self._severity = severity
		self._component = component
		self._versions = versions
		self._download = download
		self._publication_date = publication_date

	def get_name(self):
		return self._name

	def get_severity(self):
		return self._severity

	def get_component(self):
		return self._component

	def get_versions(self):
		return self._versions

	def get_download(self):
		return self._download

	def get_date(self):
		return self._publication_date

	def set_name(self, name):
		self._name = name

	def set_severity(self, severity):
		self._severity = severity

	def set_component(self, component):
		self._component = component

	def set_versions(self, versions):
		self._versions = versions

	def set_download(self, download):
		self._download = download

	def set_date(self, publication_date):
		self._publication_date = publication_date



# Colors

RED_DARK = '\033[38;5;1m'
RED = '\033[91m'
ORANGE = '\033[38;5;208m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

# Global variables

url = 'https://security.snyk.io/vuln?search='

banner = """
██▄   █    █             ▄     ▄   █        ▄          ▄▄▄▄▄   ▄███▄   ██   █▄▄▄▄ ▄█▄     ▄  █ ▄███▄   █▄▄▄▄
█  █  █    █              █     █  █         █        █     ▀▄ █▀   ▀  █ █  █  ▄▀ █▀ ▀▄  █   █ █▀   ▀  █  ▄▀
█   █ █    █         █     █ █   █ █     ██   █     ▄  ▀▀▀▀▄   ██▄▄    █▄▄█ █▀▀▌  █   ▀  ██▀▀█ ██▄▄    █▀▀▌
█  █  ███▄ ███▄       █    █ █   █ ███▄  █ █  █      ▀▄▄▄▄▀    █▄   ▄▀ █  █ █  █  █▄  ▄▀ █   █ █▄   ▄▀ █  █
███▀      ▀    ▀       █  █  █▄ ▄█     ▀ █  █ █                ▀███▀      █   █   ▀███▀     █  ▀███▀     █
                        █▐    ▀▀▀        █   ██                          █   ▀             ▀            ▀
                        ▐                                               ▀
"""

# Function to print using colors without messing up the console afterwards
#	That's why we need to add the RESET
def print_colors(text, color):
	print(f"{color}{text}{RESET}")

# Ctrl+C

def signal_handler(sig, frame):
	print_colors("\n\n[!] Exiting...", RED)
	sys.exit(1)

# Function that sorts vulnerabilities from most recent to oldest
def sort_vulns_by_date(vulnerabilities):

    def get_date_datetime(vuln):
        return datetime.strptime(vuln.get_date(), "%d %b %Y")

    sorted_vulnerabilities = sorted(vulnerabilities, key=get_date_datetime, reverse=True)

    return sorted_vulnerabilities

# Function that applies the regex to the request response to extract only the severities of the vulnerabilities found
def severities(request):
	regexSev = re.compile(r'(?<=data-v-87993300>).*?(?=<)', re.DOTALL)

	sevs = regexSev.findall(request)

	filtered_matches = [
		match.strip() for match in sevs
		if match.strip() and not re.fullmatch(r'<!---->', match.strip())
	]

	return filtered_matches

# Function that creates the list of vulnerability objects and returns it
def format_response(data, severities):

	i = 0
	j = 0

	vulns = []

	sevs = {
		'C': 'Critical',
		'H': 'High',
		'M': 'Medium',
		'L': 'Low'
	}

	if(len(data) % 5 == 0):
		while i < len(data):

			vulnerability = Vulnerability()

			vulnerability.set_name(str(data[i].strip()))
			vulnerability.set_severity(str(sevs[str(severities[j])]))
			vulnerability.set_component(str(data[i+1].strip()))
			vulnerability.set_versions(str(data[i+2].strip()))
			vulnerability.set_download(str(data[i+3].strip()))
			vulnerability.set_date(str(data[i+4].strip()))

			vulns.append(vulnerability)
			i += 5
			j += 1

	else:
		while i < len(data):

			vulnerability = Vulnerability()
			moreV = 0

			vulnerability.set_name(str(data[i].strip()))
			vulnerability.set_severity(str(sevs[str(severities[j])]))
			vulnerability.set_component(str(data[i+1].strip()))

			versions = ''

			if(data[i+3].strip().startswith('(') or data[i+3].strip().startswith('[')):
				while(data[i+2+moreV].strip().startswith('(') or data[i+2+moreV].strip().startswith('[')):
					if not versions:
						versions = data[i+2+moreV].strip()
						moreV += 1
					else:
						versions += ', ' + data[i+2+moreV].strip()
						moreV += 1

				vulnerability.set_versions(versions)

				vulnerability.set_download(str(data[i+2+moreV].strip()))
				vulnerability.set_date(str(data[i+3+moreV].strip()))

				vulns.append(vulnerability)

				i += (4+moreV)
				j += 1
			else:

				vulnerability.set_download(str(data[i+3].strip()))
				vulnerability.set_date(str(data[i+4].strip()))

				vulns.append(vulnerability)
				i += 5
				j += 1
	return vulns

# Function that makes the request, then receives the list and prints it
def make_request():
	try:
		while True:
			file_name = input("Enter the name of the file to import the data from (only .txt extension): ")
			if(file_name.lower().endswith('.txt')):
				if(os.path.isfile(file_name)):
					break
				else:
					print_colors("\n[!] File not found, please enter a valid one", ORANGE)
			else:
				print_colors("\n[!] The file extension does not match the expected one:", ORANGE)

		with open(file_name, 'r') as f:
			for line in f:
				final_url = url + line

				response = requests.get(final_url)
				content = response.text.splitlines()

				sev = severities(response.text)

				regex = re.compile(r'<\!---|<\/span|<\/body|<\/html|Snyk|Disclosed|Policies|Sell|Report|Next')

				filtered1 = [line for line in content if not regex.search(line)]

				filtered2 = next((i for i, line in enumerate(filtered1) if 'PUBLISHED' in line), None)

				if filtered2 is not None:
					relevant_content = filtered1[filtered2 + 1:filtered2 + 1001]
				else:
					relevant_content = []

				final_content = [line for line in relevant_content if 'PUBLISHED' not in line]
				final_content = [line.replace('&lt;', '<') for line in final_content]

				formatted_response = format_response(final_content, sev)
				print(f"\t\t{line}")

				sorted_vulns = sort_vulns_by_date(formatted_response)

				for vuln in sorted_vulns:
					if((datetime.now().year-3) >= datetime.strptime(vuln.get_date(), "%d %b %Y").year):
						continue
					if(vuln.get_severity()=='Critical'):
						print_colors("Vulnerability name: " + vuln.get_name(), RED_DARK)
						print_colors(f"\tSeverity: " + vuln.get_severity(), RED_DARK)
						print_colors(f"\tAffected component: " + vuln.get_component(), RED_DARK)
						print_colors(f"\tAffected versions: " + vuln.get_versions(), RED_DARK)
						print_colors(f"\tDownload: " + vuln.get_download(), RED_DARK)
						print_colors(f"\tPublication date: " + vuln.get_date(), RED_DARK)
					elif(vuln.get_severity()=='High'):
						print_colors("Vulnerability name: " + vuln.get_name(), RED)
						print_colors(f"\tSeverity: " + vuln.get_severity(), RED)
						print_colors(f"\tAffected component: " + vuln.get_component(), RED)
						print_colors(f"\tAffected versions: " + vuln.get_versions(), RED)
						print_colors(f"\tDownload: " + vuln.get_download(), RED)
						print_colors(f"\tPublication date: " + vuln.get_date(), RED)
					elif(vuln.get_severity()=='Medium'):
						print_colors("Vulnerability name: " + vuln.get_name(), ORANGE)
						print_colors(f"\tSeverity: " + vuln.get_severity(), ORANGE)
						print_colors(f"\tAffected component: " + vuln.get_component(), ORANGE)
						print_colors(f"\tAffected versions: " + vuln.get_versions(), ORANGE)
						print_colors(f"\tDownload: " + vuln.get_download(), ORANGE)
						print_colors(f"\tPublication date: " + vuln.get_date(), ORANGE)
					elif(vuln.get_severity()=='Low'):
						print_colors("Vulnerability name: " + vuln.get_name(), YELLOW)
						print_colors(f"\tSeverity: " + vuln.get_severity(), YELLOW)
						print_colors(f"\tAffected component: " + vuln.get_component(), YELLOW)
						print_colors(f"\tAffected versions: " + vuln.get_versions(), YELLOW)
						print_colors(f"\tDownload: " + vuln.get_download(), YELLOW)
						print_colors(f"\tPublication date: " + vuln.get_date(), YELLOW)
				print("\n")

	except FileNotFoundError:
		return "Error: The file does not exist."
	except IOError:
		return "Error: Cannot read the file."

# Main function
if __name__ == "__main__":
	signal.signal(signal.SIGINT, signal_handler)

	print(banner)
	print("Tool made with lots of love by m4t1. <3\n")
	time.sleep(3)
	make_request()
