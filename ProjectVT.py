import requests
import os,sys
import time

sys.stdout = open('log.txt', 'w')


apikey=''

def VT_REPORT(iresourse):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': apikey, 'resource': iresourse}
    response = requests.get(url, params=params)
    re=response.json()
    scans=re["scans"]
    return scans

def VT_SCAN(ifile):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': apikey}
    files = {'file': (ifile, open(ifile, 'rb'))}
    response = requests.post(url, files=files, params=params)
    rs=response.json();
    report=VT_REPORT(rs["resource"])
    return report
def find_results(reports):
 i=0
 vir={}
 for name1 in reports:
    if reports[name1]["detected"]:
	vir[i]=reports[name1]["result"]
	i=i+1
 return vir
def find_decryptor(dir1,virs1):
  for dname in os.listdir(dir1):
    path1 = os.path.join(dir1, dname)
    if os.path.isfile(path1):
        s= path1


def walk(dir):
  for name in os.listdir(dir):
    path = os.path.join(dir, name)
    if os.path.isfile(path):
        reports=VT_SCAN(path)
	time.sleep(40)
	virs=find_results(reports)
	print name
	print virs
	find_decryptor('./decryptors',virs)
    else:
        walk(path)

try:
    walk('./samples')
finally:
    sys.stdout.close()



