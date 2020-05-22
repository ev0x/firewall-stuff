#!/usr/bin/env python3
import string
import re
import mmap
import csv
import ipaddress

def hostcalc(raw_src,src,route):
    r_src = []
    isipam = 'No'
    for i in object_network:
        if raw_src in i:
            r_src.append(i)

    # look through the object_network
    if not r_src:
        for i in object_group_network:
            if raw_src in i:
                r_src.append(i)

    # try:
    #     print(r_src[0][6])
    # except:
    #     pass
    if not r_src:
        # x.x.x.x/x.x.x.x (x.x.x.x/x)
        if re.match('[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}\/[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}\s.+', raw_src):
            src = raw_src.split('(')[1].split(')')[0] # extract like x.x.x.x/x
            for k,v in data_routes.items():
                host = str(src.split('/')[0])
                if ipaddress.ip_address(host) in ipaddress.ip_network(k):
                    route = "[" + v.split(' ')[0] + "] "

        # x.x.x.x (x.x.x.x/x)
        if not src:
            if re.match('[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}\s\([0-9.\/)]+', raw_src):
                obj = ""
                src = raw_src.split('(')[1].split(')')[0] # extract like x.x.x.x/x
                for i in object_network:
                    if raw_src.split(' ')[0] in i:
                        obj = i[0]

                for k,v in data_routes.items():
                    host = str(src.split('/')[0])
                    if ipaddress.ip_address(host) in ipaddress.ip_network(k):
                        route = "[" + v.split(' ')[0] + "] "
                if not obj == "":
                    src = obj + " [" + src + "]"
                else:
                    if src.split('/')[0] in data_ipam:
                        src = src + " [" + data_ipam[src.split('/')[0]] + "]"

        if not src:
            if re.match('[a-zA-Z0-9_-]{5,100}\s\([0-9.\/)]+', raw_src):
                src = raw_src
                for k,v in data_routes.items():
                    host = str(src.split('(')[1].split('/')[0].replace(')',''))
                    if ipaddress.ip_address(host) in ipaddress.ip_network(k):
                        route = "[" + v.split(' ')[0] + "] "

    if len(r_src) >= 1:
        if all(i[3] == i[3] for i in r_src):
            route = "[" + r_src[0][3] + "] "
        else:
            route = "[MULTIPLE ZONES?] "

        if len(r_src) > 4:
            src = r_src[0][0] + " [" + r_src[0][5] + "]"
        else:
            src = r_src[0][0] + " [" + ", ".join(i[2] for i in r_src) + "]"

    return(src,route)


# pull the ipam ip data into a dict
with open('rules.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    rules = [i for i in reader]

# pull the ipam ip data into a dict
with open('ipam_extract.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data_ipam = {k:v for k, v in reader}

# pull in the object network
with open('object_network.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    object_network = [i for i in reader]

# pull in the object-group network
with open('object-group_network.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    object_group_network = [i for i in reader]

# pull in the object group services
with open('object-group_services.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    object_group_services = [i for i in reader]

# pull the routes from the firewall
with open('routes.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data_routes = {k:v for k, v in reader}

# pull the routes from the firewall
with open('allfwroutes.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    all_routes = {k:v for k, v in reader}

with open('acl_comments.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    for rule in rules:
        # ['Policy', 'Number', 'Status', 'Name', 'Source Zone/Interface', 'Source', 'Destination Zone/Interface', 'Destination', '
        # Service', 'Action']
        # Extract everything
        raw_policy = rule[0]
        raw_number = rule[1]
        raw_status = rule[3]
        raw_srcint = rule[4]
        raw_src = rule[5]
        raw_dstint = rule[6]
        raw_dst = rule[7]
        raw_svc = rule[8]
        raw_act = rule[9]
        r_src = []

        polNum = raw_policy + "_" + raw_number
        # processing the src
        src = ""
        if raw_src == "Any":
            src = "ANY"
            src_route = "[ANY] "

        if src == "":
            route = "[UNKNOWN ZONE] "
            # check hostcalc
            src,src_route = hostcalc(raw_src,src,route)

        # processing the dst
        dst = ""
        if raw_dst == "Any":
            dst = "ANY"
            dst_route = "[ANY] "

        if dst == "":
            route = "[UNKNOWN ZONE] "
            # check hostcalc
            dst,dst_route = hostcalc(raw_dst,dst,route)

        if raw_act == "ACCEPT":
            act = "This rule allows access from zone "
        else:
            act = "This rule denies access from zone "


        # processing the svc
        svc = ""
        secure = True
        if raw_svc == "Any":
            svc = "ANY"
            secure = False

        if svc == "":
            r = []
            for i in object_group_services:
                if raw_svc in i:
                    r.append(i)

            if len(r) > 5:
                svc = r[0][0] + " [" + r[0][4] + "]"
            else:
                try:
                    svc = r[0][0] + " [" + ', '.join(i[2] + "/" + i[1] for i in r) + "]"
                except:
                    svc = raw_svc

            if len(svc) == 0:
                svc = raw_svc

        rule = act + src_route + src + " to zone " + dst_route + dst + " for service " + svc
        src_note = ""
        dest_note = ""
        svc_note = ""

        if raw_act == "ACCEPT":
            extract_counts = re.compile("""(?P<hosts>\d+(?=\shosts)).+
            (?P<networks>\d+(?=\snetworks)).+
            (?P<objects>\d+(?=\sobjects))
            """, re.VERBOSE)

            if src == "ANY":
                src_note = ". Why is the source ANY here can this be defined"
            elif '/' in src:
                if int(re.sub('[^0-9]', '', src.split('/')[1])) <= 28:
                    src_note = ". Does this whole src network require this access? Can this be restricted in some way?"
            else:
                re_src = extract_counts.search(src)
                if hasattr(re_src, 'groups'):
                    if int(re_src.group('hosts')) >= 10:
                        src_note = '. Validate the src hosts here'
                    if int(re_src.group('networks')) >= 1:
                        src_note = src_note + ". Does the whole src networks require this access? Can this be restricted in some way?"
                    if int(re_src.group('objects')) >= 4:
                        src_note = src_note + ". Validate the src objects used here"


            if dst == "ANY":
                dest_note = ". Why is the dest ANY here can this be defined"
            elif '/' in dst:
                if int(re.sub('[^0-9]', '', dst.split('/')[1])) <= 28:
                    dest_note = ". Does this whole dest network require this access? Can this be restricted in some way?"
            else:
                re_dst = extract_counts.search(dst)
                if hasattr(re_dst, 'groups'):
                    if int(re_dst.group('hosts')) >= 10:
                        dest_note = '. Validate the dest hosts here'
                    if int(re_dst.group('networks')) >= 1:
                        dest_note = dest_note + ". Does the whole dest networks require this access? Can this be restricted in some way?"
                    if int(re_dst.group('objects')) >= 4:
                        dest_note = dest_note + ". Validate the dest objects used here"

            if svc == "ANY":
                svc_note = ". Why is the service ANY here this should be defined"

            if 'tcp-www' in svc:
                svc_note = '. Why is HTTP used here? This is not secure. Can HTTPS be used?'
            elif 'www/tcp' in svc:
                svc_note = '. Why is HTTP used here? This is not secure. Can HTTPS be used?'

            if 'tcp-smtp' in svc:
                svc_note = svc_note + '. Why is SMTP used here? This is not secure. Can SMTPS be used?'

            if 'telnet/tcp' in svc:
                svc_note = svc_note + '. Why is telnet used here? This is not secure. Can a secure protocol be used?'

            if 'ftp/tcp' in svc:
                svc_note = svc_note + '. Why is ftp used here? This is not secure. Can a secure protocol be used unless this is already using SSL?'

        rule = rule + src_note + dest_note + svc_note

        ip = re.findall('[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}', rule)
        matched = ''
        if len(ip) > 0:
            matched = 'No'
            for i in ip:
                for k,v in all_routes.items():
                    if ipaddress.ip_address(i) in ipaddress.ip_network(k):
                        matched = ''

        print(rule)
        writer.writerow([polNum, rule, matched])
