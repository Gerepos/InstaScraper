from bs4 import BeautifulSoup
import requests
from requests import get
import csv
from time import sleep
from array import *
from socket import error as SocketError
import errno
import os
import argparse
import sys
from urllib.parse import urlparse

# proxylist/mechanize are optional
try:
    from proxylist import ProxyList
except Exception:
    ProxyList = None

try:
    from mechanize import Browser  # optional
    import mechanize
except Exception:
    Browser = None
    mechanize = None

try:
    import cookielib
except Exception:
    import http.cookiejar as cookielib

import logging
import random
import re
fileDir = os.path.dirname(os.path.abspath(__file__))   # Directory of the Module

R = '\033[31m'  # red
G = '\033[32m'  # green
# tells the user to use proxy (-X or -- proxy )
parser = argparse.ArgumentParser(description='Instagram email scraper (profile + viewer fallbacks)')
parser.add_argument('-X','--proxy', dest='proxy', help='Proxy list file (one proxy per line)')
parser.add_argument('-u','--user', dest='single_user', help='Single Instagram username or profile URL to scrape')
parser.add_argument('--playwright', dest='use_playwright', action='store_true', help='Use Playwright to render JS where needed (optional)')
parser.add_argument('--verbose', dest='verbose', action='store_true', help='Verbose logging')
args = parser.parse_args()

#Testing function
#def test_scraper():
#    assert init_scraper() == True
#    print("===========================CODE BUILD SUCCESSFUL===========================")

#Convert list to string
def listToString(s):
    str1 = ""
    # handle if s is already a string or a sequence
    if isinstance(s, str):
        return s
    for ele in s:
        str1 += ele
    # return string
    return str1

#proxy grabber
# mechanize is optional; if available we won't depend on it for proxy checks
if Browser:
    try:
        brows = Browser()
        brows.set_handle_robots(False)
        brows._factory.is_html = True
        brows.set_cookiejar(cookielib.LWPCookieJar())
    except Exception:
        brows = None
else:
    brows = None

# If proxy option was passed but proxylist not installed, we will fallback to simple loader
if args.proxy and ProxyList is None:
    logging.info('proxylist not installed; using simple proxy file loader')
useragents = [
           'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.19) Gecko/20081202 Firefox (Debian-2.0.0.19-0etch1)',
           'Opera/9.80 (J2ME/MIDP; Opera Mini/9.80 (S60; SymbOS; Opera Mobi/23.348; U; en) Presto/2.5.25 Version/10.54',
           'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.12 Safari/535.11',
           'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.6 (KHTML, like Gecko) Chrome/16.0.897.0 Safari/535.6']
brows.addheaders = [('User-agent',random.choice(useragents))]
# set_handle_refresh is mechanize-specific; only call if we have the mechanize module
if 'mechanize' in globals() and hasattr(mechanize, '_http'):
    try:
        brows.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)
    except Exception:
        # non-fatal: continue without refresh handling
        pass
proxyList = args.proxy
def check_dns(host='www.instagram.com'):
    import socket
    try:
        socket.getaddrinfo(host, 443)
        return True
    except Exception:
        return False

def load_proxies_from_file(path):
    proxies_out = []
    try:
        with open(path, 'r') as fh:
            for ln in fh:
                l = ln.strip()
                if not l or l.startswith('#'):
                    continue
                proxies_out.append(l)
    except Exception:
        logging.warning(f"Could not read proxy file: {path}")
    return proxies_out

def choose_proxy(proxies_list):
    if not proxies_list:
        return None
    return random.choice(proxies_list)

proxies = None
if proxyList:
    proxies = load_proxies_from_file(proxyList)

# Logging config
if args.verbose:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)

# optional Playwright availability
use_playwright = args.use_playwright
try:
    if use_playwright:
        from playwright.sync_api import sync_playwright
except Exception:
    if use_playwright:
        logging.warning('Playwright requested but not installed; continuing without it')
    use_playwright = False
#Decode Cloudflare Email Obfuscation



def find_emails_in_text(text):
    # find mailto links first
    emails = set()
    for m in re.findall(r'mailto:([\w.+-]+@[\w.-]+)', text, flags=re.IGNORECASE):
        emails.add(m)
    # plain emails
    for m in re.findall(r'([\w.+-]+@[\w.-]+\.[a-zA-Z]{2,})', text):
        emails.add(m)
    return list(emails)


def fetch_with_playwright(url, timeout=15000):
    # Synchronous Playwright fetcher
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=timeout)
            content = page.content()
            browser.close()
            return content
    except Exception as e:
        logging.warning(f"Playwright fetch failed for {url}: {e}")
        raise


# Replace and extend is_email_from_same_domain with a normalized domain comparison
def is_email_from_same_domain(email, url):
    """Check if the given email belongs to the domain of the viewer site at the given URL.
    Normalize domains (strip www, lowercase) and allow subdomain matches.
    """
    try:
        def norm_host(h):
            if not h:
                return ''
            h = h.lower()
            if h.startswith('www.'):
                h = h[4:]
            if ':' in h:
                h = h.split(':')[0]
            return h

        domain = norm_host(urlparse(url).netloc)
        email_domain = norm_host(email.split('@')[-1])
        if not domain or not email_domain:
            return False
        if email_domain == domain:
            return True
        # email_domain may be a subdomain of domain or vice versa; block if they match closely
        if email_domain.endswith('.' + domain) or domain.endswith('.' + email_domain):
            return True
        return False
    except Exception:
        return False


def explain_status(status, lang='de'):
    try:
        s = int(status)
    except Exception:
        return str(status)
    if s == 200:
        return 'erfolgreich' if lang == 'de' else 'successful'
    if s == 403:
        return 'zugriff verweigert / blockiert' if lang == 'de' else 'forbidden / blocked'
    if s == 404:
        return 'nicht gefunden' if lang == 'de' else 'not found'
    if s == 429:
        return 'zu viele Anfragen / rate-limited' if lang == 'de' else 'too many requests / rate-limited'
    if 500 <= s <= 599:
        return ('Serverfehler' if lang == 'de' else 'server error') + f' ({s})'
    return f'HTTP {s}'


def site_status_message(url, status, lang='de'):
    expl = explain_status(status, lang)
    if lang == 'de':
        return f"Seite {url} lieferte HTTP-Status {status} ({expl})."
    else:
        return f"Site {url} returned HTTP status {status} ({expl})."


def query_viewers(username, session, proxy=None):
    """Query a list of viewer services for the given username and return the first found email or None.
    This version discards emails that belong to the viewer site's own domain.
    """
    viewers = [
        # Inflact profile viewer (expects username at end)
        lambda u: (f"https://inflact.com/instagram-viewer/profile/{u}/", {}),
        # Stealthgram viewer (has a search endpoint)
        lambda u: (f"https://stealthgram.com/{u}", {}),
        # Instapv viewer
        lambda u: (f"https://instapv.com/{u}", {}),
        # PathSocial web viewer (profile preview)
        lambda u: (f"https://www.pathsocial.com/de/free-instagram-tools/web-viewer-for-instagram/?username={u}", {}),
    ]

    headers = {'User-Agent': random.choice(useragents)}
    results = []
    success_count = 0
    for make in viewers:
        url, extra = make(username)
        try:
            # perform request
            if proxy:
                session.proxies.update({'http': proxy, 'https': proxy})
            r = session.get(url, timeout=15, headers=headers)
            status = r.status_code
            if status == 200:
                success_count += 1
            # record status
            results.append((url, True, status, None))

            if status == 200:
                found = find_emails_in_text(r.text)
                if found:
                    candidate = found[0]
                    # discard if email domain matches the viewer site's domain
                    if is_email_from_same_domain(candidate, url):
                        results.append((url, False, status, f'Discarded email from site domain: {candidate}'))
                        # continue searching other viewers
                        continue
                    return candidate, results, success_count
            else:
                # non-200 means no useful content
                continue
        except requests.exceptions.SSLError as e:
            results.append((url, False, None, f'SSL-Fehler: {e}'))
            continue
        except requests.exceptions.RequestException as e:
            results.append((url, False, None, str(e)))
            continue
    return None, results, success_count

# insert language helpers here so they are defined before init_scraper

def ask_language_choice(username):
    """Ask the user whether they want German (1) or English (2) for messages for this username."""
    while True:
        try:
            choice = input(f"Sprache für '{username}' wählen / choose language for '{username}':\n1) Deutsch\n2) English\nBitte 1 oder 2 eingeben (default 1): ")
        except EOFError:
            # non-interactive environment: default to German
            return 'de'
        if not choice:
            return 'de'
        choice = choice.strip()
        if choice == '1':
            return 'de'
        if choice == '2':
            return 'en'
        print("Ungültige Auswahl / invalid choice. Bitte 1 oder 2 eingeben.")


def tr(msg_key, lang='de', **kwargs):
    """Translation helper for a small set of message keys.
    msg_key: string key
    lang: 'de' or 'en'
    kwargs: format args for the message
    """
    messages = {
        'requesting_profile': {
            'de': "Anfrage des Instagram-Profils {url}",
            'en': "Requesting Instagram profile {url}"
        },
        'proxylist_not_installed': {
            'de': 'proxylist nicht installiert; verwende einfache Proxy-Datei.',
            'en': 'proxylist not installed; using simple proxy file loader.'
        },
        'instagram_request_failed': {
            'de': "Instagram-Anfrage für {user} fehlgeschlagen: {err}",
            'en': "Instagram request for {user} failed: {err}"
        },
        'checked_instagram_found': {
            'de': "Auf Instagram geprüft: E-Mail im Quelltext gefunden.",
            'en': "Checked Instagram: email found in page source."
        },
        'checked_instagram_not_found': {
            'de': "Instagram-Profil überprüft: keine sichtbare E-Mail gefunden.",
            'en': "Checked Instagram profile: no visible email found."
        },
        'ssl_error_site': {
            'de': "Seite {url} konnte wegen eines SSL-Zertifikatfehlers nicht abgefragt werden.",
            'en': "Site {url} could not be fetched due to an SSL certificate error."
        },
        'site_http_status': {
            'de': "Seite {url} lieferte HTTP-Status {status} (nicht erfolgreich).",
            'en': "Site {url} returned HTTP status {status} (not successful)."
        },
        'site_unreachable': {
            'de': "Seite {url} konnte nicht erreicht werden: {err}",
            'en': "Site {url} could not be reached: {err}"
        },
        'result_none': {
            'de': "Ergebnis: Keine E-Mail gefunden auf Instagram oder den Viewer‑Seiten.",
            'en': "Result: No email found on Instagram or the viewer sites."
        },
        'warning_no_email': {
            'de': "Warnung: Es wurde keine E‑Mail gefunden. Mögliche Gründe: die Seite zeigt keine öffentliche E‑Mail, die Viewer‑Dienste blockieren Anfragen (403/404), oder es besteht ein SSL/CA‑Problem (siehe Hinweise).",
            'en': "Warning: No email was found. Possible reasons: the profile doesn't expose a public email, the viewer services block requests (403/404), or there is an SSL/CA problem (see notes)."
        },
        'short_guide': {
            'de': "Kurz-Anleitung: 1) SSL-Zertifikate in WSL prüfen/installieren, 2) Playwright (--playwright) verwenden, 3) andere Proxies testen oder Headers anpassen.",
            'en': "Short guide: 1) Check/install SSL certificates in WSL, 2) use Playwright (--playwright), 3) try other proxies or adjust headers."
        },
        'total_emails_found': {
            'de': 'Anzahl gefundener E-Mails: {n}',
            'en': 'Total Emails Found: {n}'
        },
        'total_emails_not_found': {
            'de': 'Anzahl nicht gefundener E-Mails: {n}',
            'en': 'Total Emails NOT Found: {n}'
        }
    }
    tpl = messages.get(msg_key, {})
    text = tpl.get(lang, tpl.get('de', msg_key))
    try:
        return text.format(**kwargs)
    except Exception:
        return text

def init_scraper():
    emails = []
    proxy = proxies
    user = 0
    found_emails = 0
    email_not_exist = 0
    # If a single user was passed via CLI, use that instead of input.csv
    single = None
    if args.single_user:
        u = args.single_user.strip()
        # if full URL provided, extract the username
        if u.startswith('http'):
            u = u.rstrip('/').split('/')[-1]
        single = [u]
        csv_f = [single]
    else:
        try:
            f = open(fileDir + '/input.csv')
            csv_f = csv.reader(f)
        except Exception:
            print("input.csv not found and no --user provided. Exiting.")
            return False
    for row in csv_f:
        user += 1
        sleep(1)
        listToString(row)
        try:
            # primary: Instagram profile page
            uname = listToString(row)
            if args.single_user and isinstance(args.single_user, str) and args.single_user.startswith('http') and 'instagram.com' in args.single_user:
                insta_url = args.single_user.rstrip('/')
            else:
                insta_url = f"https://www.instagram.com/{uname}/"

            # Ask language preference for this username (per user interactive prompt)
            lang = ask_language_choice(uname)

            sess = requests.Session()
            # pick a proxy for this session if proxy list provided
            chosen = None
            if proxies:
                chosen = choose_proxy(proxies)
                if chosen:
                    sess.proxies.update({'http': chosen, 'https': chosen})

            response = None
            try:
                logging.info(tr('requesting_profile', lang, url=insta_url))
                if use_playwright:
                    response_text = fetch_with_playwright(insta_url)
                    response = type('R', (), {'status_code': 200, 'text': response_text})
                else:
                    response = sess.get(insta_url, timeout=15, headers={'User-Agent': random.choice(useragents)})
            except requests.exceptions.RequestException as e:
                logging.warning(tr('instagram_request_failed', lang, user=uname, err=str(e)))

            # Parse Instagram page for emails (unlikely but try)
            found_any = False
            if response is not None and getattr(response, 'status_code', None) == 200:
                found = find_emails_in_text(response.text)
                if found:
                    emails.append([uname, found[0]])
                    found_emails += 1
                    found_any = True

            # If not found on Instagram, try viewer services
            steps = []
            step_no = 1
            if found_any:
                steps.append(f"{step_no}. " + tr('checked_instagram_found', lang))
                step_no += 1
            else:
                steps.append(f"{step_no}. " + tr('checked_instagram_not_found', lang))
                step_no += 1

                v, results, success_count = query_viewers(uname, sess, chosen)

                # Log each viewer result in steps (localized, numbered)
                for url, ok, status, err in results:
                    # If the email was found but discarded because it belonged to site domain, log that
                    if err and isinstance(err, str) and err.startswith('Discarded email'):
                        if lang == 'de':
                            steps.append(f"{step_no}. Seite {url} lieferte eine vom Viewer stammende E-Mail und wurde verworfen: {err.split(':',1)[1].strip()}")
                        else:
                            steps.append(f"{step_no}. Site {url} returned an email that belongs to the viewer site and was discarded: {err.split(':',1)[1].strip()}")
                        step_no += 1
                        continue

                    if ok and status == 200:
                        steps.append(f"{step_no}. " + site_status_message(url, status, lang))
                        step_no += 1
                    elif err and ('SSL-Fehler' in str(err) or 'SSL' in str(err)):
                        steps.append(f"{step_no}. " + tr('ssl_error_site', lang, url=url))
                        step_no += 1
                    else:
                        if status:
                            steps.append(f"{step_no}. " + site_status_message(url, status, lang))
                        else:
                            steps.append(f"{step_no}. " + tr('site_unreachable', lang, url=url, err=err))
                        step_no += 1

                # Append successful pages count
                steps.append(f"{step_no}. { 'Erfolgreich abgeglichene Seiten:' if lang=='de' else 'Successful pages:' } {success_count}")
                step_no += 1

                if v:
                    emails.append([uname, v])
                    found_emails += 1
                    # print steps localized, with blank line before steps and after
                    print('')
                    for s in steps:
                        print(s)
                        print('')
                    print('')
                    continue
                else:
                    # no email found anywhere: append result + warning to steps (so ordering is consistent)
                    steps.append(f"{step_no}. " + tr('result_none', lang))
                    step_no += 1
                    # Append warning and guide as subsequent non-numbered lines (keep them numbered optionally)
                    steps.append(f"{step_no}. " + tr('warning_no_email', lang))
                    step_no += 1
                    steps.append(f"{step_no}. " + tr('short_guide', lang))
                    step_no += 1

                    emails.append([uname, 'null'])
                    email_not_exist += 1

                    # print steps localized, with blank line before and after steps
                    print('')
                    for s in steps:
                        print(s)
                        print('')
                    print('')
                    continue
        except SocketError as e:
            if e.errno != errno.ECONNRESET:
                raise
            print('The host has reset the connection due to rate limits.')
            continue
        except requests.exceptions.RequestException as e:
            # attempt fallback: try scraping Instagram profile directly
            uname = listToString(row)
            print(f"Primary source failed for {uname}: {e}. Trying Instagram profile fallback...")
            try:
                headers = {'User-Agent': random.choice(useragents)}
                sess = requests.Session()
                if proxies:
                    chosen = choose_proxy(proxies)
                    if chosen:
                        sess.proxies.update({'http': chosen, 'https': chosen})
                r2 = sess.get(f"https://www.instagram.com/{uname}/", timeout=15, headers=headers)
                if r2.status_code == 200:
                    found = find_emails_in_text(r2.text)
                    if found:
                        print(f"Found email(s) on Instagram profile for {uname}: {found}")
                        emails.append([uname, found[0]])
                        found_emails += 1
                        continue
                # no emails found on Instagram profile
                print(f"No email found on Instagram profile for {uname}. Skipping.")
                emails.append([uname, 'null'])
                email_not_exist += 1
                continue
            except Exception as e2:
                print(f"Fallback Instagram request failed for {uname}: {e2}. Skipping entry.")
                emails.append([uname, 'null'])
                email_not_exist += 1
                continue
        # (old theinstaprofile / Cloudflare decoding logic removed)
    with open("Output.csv", "w+") as my_csv:
        csvWriter = csv.writer(my_csv, delimiter=',')
        for i in range(len(emails)):
            if (emails[i][1] != 'null'):
                csvWriter.writerow(emails[i])
            else:
                pass
    # localized totals in default German (script-level); keep English alternative as well
    print('')
    print(tr('total_emails_found', 'de', n=found_emails))
    print(tr('total_emails_not_found', 'de', n=email_not_exist))
    print('')
    return True
try:
    init_scraper()
except KeyboardInterrupt:
    # Attempt to write partial results if possible
    try:
        print('\nKeyboardInterrupt received — attempting to write partial Output.csv')
        # try to salvage emails variable from locals if present
        if 'emails' in locals():
            with open("Output.csv", "w+") as my_csv:
                csvWriter = csv.writer(my_csv, delimiter=',')
                for i in range(len(emails)):
                    if (emails[i][1] != 'null'):
                        csvWriter.writerow(emails[i])
        print('Partial output written to Output.csv')
    except Exception:
        pass
    raise

# Nach Abschluss: Inhalt von Output.csv ausgeben (deutsch)
try:
    print('\nInhalt von Output.csv:')
    with open('Output.csv', 'r') as f:
        lines = f.read().strip().splitlines()
        if not lines:
            print('(Output.csv ist leer)')
        else:
            for i, ln in enumerate(lines, start=1):
                print(f"{i}. {ln}")
except Exception:
    print('Konnte Output.csv nicht lesen.')
