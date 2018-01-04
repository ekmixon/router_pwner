#!/usr/bin/python

import os

import scanners

# Hardcoded (will dynamic later)
enable_brute_forcer = True
ip_file = "/root/PycharmProjects/scanner/static/ips"


def get_urls(infile):
    urls = []

    with open(infile) as f:
        for line in f.readlines():
            u = line.strip().lower().rstrip("/")

            if not u.startswith("http"):
                url["url"] = "http://" + url["url"]

            urls.append(u)

    return urls


def get_bf_creds():
    uns = [""]
    pws = [""]

    with open(os.path.join(os.getcwd(), "conf", "usernames")) as f:
        for i in f.readlines():
            if i.strip() not in uns:
                uns.append(i.strip())

    with open(os.path.join(os.getcwd(), "conf", "passwords")) as f:
        for i in f.readlines():
            if i.strip() not in pws:
                pws.append(i.strip())

    return uns, pws


if __name__ == "__main__":
    url_list = get_urls(ip_file)
    un_list, pw_list = get_bf_creds()

    for url in url_list:
        res = scanners.get_id(url)

        if not res:
            continue

        res.load_creds(un_list, pw_list)
        scan_res = res.start()



