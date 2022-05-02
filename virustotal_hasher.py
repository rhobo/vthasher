import requests
import re

#pattern to match
pattern = "^[A-Za-z0-9]*$"

#check if hash matches md5 length
def hash_is_md5(_hash) -> bool:
    return len(_hash) == 32
#check if hash matches sha1 length
def hash_is_sha1(_hash) -> bool:
    return len(_hash) == 40

print("Please input your VT API key: ")
input1 = input()
#print("Your VT API key is: " + input1)
print("Please input the hash you wish to check: ")
input2 = input()
#print("Your hash is: " + input2)

#check hash against pattern
state = bool(re.match(pattern, input2))
state2 = hash_is_md5(input2)
state3 = hash_is_sha1(input2)

if state == True & state2 == True:
    print("Hash is valid MD5. Checking VT..")
elif state == True & state3 == True:
    print("Hash is valid SHA1. Checking VT..")
else:
    print("Hash is invalid, stopping.")
    exit()

headers = {
    "Accept": "application/json",
    "x-apikey": input1
}

url = "https://www.virustotal.com/api/v3/search?query=" + input2

response = requests.get(url, headers=headers)
jsonResponse = response.json()

if response.status_code == 200:
    print("API response code: " + str(response.status_code))
else:
    print("API communication failed, code: " + str(response.status_code) + ". Stopping")
    exit()

if len(jsonResponse["data"]) == 0:
    print("No AV engines have indicated that this file is malicious. File is clean.")
    exit()
else:
    avcount = jsonResponse["data"][0]["attributes"]["last_analysis_stats"]["malicious"]

#print response from VT API.
for key, value in jsonResponse.items():
    if avcount >= 5:
        print("Your hash has been marked malicious by " + str(avcount) + " AV engines.")
        exit()
    if avcount < 5 and avcount > 0:
        print("Your hash has been marked by " + str(avcount) + " AV engines. The file may be malicious.")
        exit()
    else:
        print("No AV engines have indicated that this file is malicious. File is clean.")
        exit()