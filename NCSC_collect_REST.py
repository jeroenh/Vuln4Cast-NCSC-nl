import requests
# import pandas as pd
# import numpy as numpy
import csv
import json
from lxml import html
import tqdm

global NCSC_advisories, version
# version = '+[1.00]'
# version = '+%5B1.00%5D'
version = '' # collect the latest version

# plain version: https://advisories.ncsc.nl/rest/advisory?ref=NCSC-2014-0002+%5B1.00%5D&format=plain
# XML version: https://advisories.ncsc.nl/rest/advisory?ref=NCSC-2014-0002+%5B1.00%5D&format=xml
# htmlified version: https://advisories.ncsc.nl/rest/advisory?ref=NCSC-2014-0002+%5B1.00%5D&format=htmlified
# Loop over years and advisories

# 2014: 0821
# 2015: 1096
# 2016: 1159
# 2017: 1116
# 2018: 1135
# 2019: 0991
# 2020: 0952
#  max: 7270 
#total: 7235


def testRun():
    page = requests.get("https://advisories.ncsc.nl/rest/advisory?ref=NCSC-2020-0926+%5B1.00%5D&format=htmlified")
    data = page.json()
    advisory_info = {}
    advisory_info['id']         = data['name']
    advisory_info['version']    = data['version']
    advisory_info['creation_date'] = data['history'][0]['date']
    advisory_info['title']      = data['title_html']
    advisory_info['CVEs']       = data['cve_ids']
    advisory_info['probability_level'] = data['probability_level']
    advisory_info['probability_matrix'] = data['probability_matrix']
    advisory_info['damage_level'] = data['damage_level']
    advisory_info['damage_matrix'] = data['damage_matrix']
    print(advisory_info)

def fetchYears():
    
    for year in (range(2019,2024)):
        advisories = []
        fail_count = 0
        # we use a range 1300 because numbering is not always done consecutively.
        # loop breaking is done on 5 consecutive missed advisories.
        for num in tqdm.tqdm(range(1,1300)):
            adv = 'NCSC-' + str(year) + '-' + str(num).zfill(4)
            page = requests.get('https://advisories.ncsc.nl/rest/advisory?ref=' + adv + version + '&format=htmlified')
        
            # Use fail count to determine the end of the range of advisories
            if 'Failed' in page.text:
                # print(adv + ' could not be found.')
                fail_count += 1
                if fail_count == 5:
                    break
                continue
            fail_count = 0

            # Read data 
            data = page.json()
            advisory_info = {}
            advisory_info['id']         = data['name']
            advisory_info['version']    = data['version']
            advisory_info['creation_date'] = data['history'][0]['date']
            advisory_info['title']      = data['title_html']
            advisory_info['CVEs']       = data['cve_ids']
            advisory_info['probability_level'] = data['probability_level']
            advisory_info['probability_matrix'] = data['probability_matrix']
            advisory_info['damage_level'] = data['damage_level']
            advisory_info['damage_matrix'] = data['damage_matrix']

            # Display advisory ID and add data to dataframe
            # print(advisory_info['id'] + ' ' + advisory_info['version'])
            advisories.append(advisory_info)
        csvfile = csv.DictWriter(open('NCSC_advisories-%s.csv' % year,'w',newline=''), fieldnames=advisories[0].keys())
        csvfile.writeheader()
        for l in advisories:
            csvfile.writerow(l)

    # Write all data to file so that we can open it in a DataFrame later
    # NCSC_advisories = pd.DataFrame(columns=['id', 'version', 'title', 'CVEs', 'probability_matrix','damage_matrix'])
    
def combineFiles():
    import glob
    totalcsv = open("NCSC-2014-2023.csv",'w',newline='')
    totalcsv.write("id,version,creation_date,title,CVEs,probability_level,probability_matrix,damage_level,damage_matrix\n")
    for f in glob.glob("./NCSC_advisories-*.csv"):
        with open(f, "r") as csvyearfile:
            csvyearfile = iter(csvyearfile)
            next(csvyearfile) # skip the header line
            for row in csvyearfile:
                totalcsv.write(row)

    # print(NCSC_advisories)

if __name__ == '__main__':
    # fetchYears()
    combineFiles()
    # testRun()