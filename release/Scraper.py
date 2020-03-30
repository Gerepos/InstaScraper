from bs4 import BeautifulSoup
from requests import get
import csv
from time import sleep
from array import *
from socket import error as SocketError
import errno
import pytest
import os
import cfscrape
from lxml.html import fromstring
import requests
from itertools import cycle
import traceback
fileDir = os.path.dirname(os.path.abspath(__file__))   # Directory of the Module

#Testing function
#def test_scraper():
#    assert init_scraper() == True
#    print("===========================CODE BUILD SUCCESSFUL===========================")

#Convert list to string
def listToString(s):
    str1 = ""
    for ele in s:
        str1 += ele
    # return string
    return str1

#Decode Cloudflare Email Obfuscation


def decodeEmail(e):
    de = ""
    k = int(e[:2], 16)
    for i in range(2, len(e)-1, 2):
        de += chr(int(e[i:i+2], 16) ^ k)
    #print de
    return de

#Grabs proxies from the website

def get_proxies():
    url = 'https://free-proxy-list.net/'
    response = requests.get(url)
    parser = fromstring(response.text)
    proxies = set()
    for i in parser.xpath('//tbody/tr')[:10]:
        if i.xpath('.//td[7][contains(text(),"yes")]'):
            #Grabbing IP and corresponding PORT
            proxy = ":".join([i.xpath('.//td[1]/text()')[0], i.xpath('.//td[2]/text()')[0]])
            proxies.add(proxy)
    return proxies

proxies = get_proxies()
proxy_pool = cycle(proxies)

def init_scraper():
    emails = []
    proxy = next(proxy_pool)
    user = 0
    found_emails = 0
    email_not_exist = 0
    f = open(fileDir + '/input.csv')
    csv_f = csv.reader(f)
    for row in csv_f:
        user += 1
        sleep(1)
        listToString(row)
        try:
            #Get Cloudflare tokens with proxy
            scraper = cfscrape.create_scraper()
            response = scraper.get(
                "https://www.theinstaprofile.com/email/" + listToString(row),proxies={"http": proxy, "https": proxy})
        except SocketError as e:
            if e.errno != errno.ECONNRESET:
                raise
            pass
            print('The host has reset the connection due to rate limits.')
        soup = BeautifulSoup(response.content, 'html.parser')
        h = soup.findAll('h1')
        #print h
        #print h
        try:
            a = h[1].find('a', href='/cdn-cgi/l/email-protection')
            decode = a['data-cfemail']
            print('Found! for: ' + listToString(row))
            print listToString(row), decodeEmail(decode)
            emails.append([listToString(row), decodeEmail(decode)])
            found_emails += 1
            #print emails
        except:
            print('Not found for influencer: ' + listToString(row))
            emails.append([listToString(row), 'null'])
            email_not_exist += 1
            #print emails
    with open("Output.csv", "w+") as my_csv:
        csvWriter = csv.writer(my_csv, delimiter=',')
        for i in range(len(emails)):
            if (emails[i][1] != 'null'):
                csvWriter.writerow(emails[i])
            else:
                pass
    print('Total Emails Found: ' + str(found_emails))
    print('Total Emails NOT Found: ' + str(email_not_exist))
    return True
init_scraper()
