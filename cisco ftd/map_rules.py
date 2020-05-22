#!/usr/bin/env python3
import string
import re
import mmap
import csv
import ipaddress

with open('config.txt', 'r') as f:
    data = f.read()

vlan_map = {
    '11': 'A',
    '311': 'B',
    '511': 'C'
}

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

ace_raw = re.findall('access-list\sCSM_FW_ACL_\s.+', data)
hostname = re.findall('hostname\s.+', data)

print("Firewall Host: " + hostname[0].split()[1])
print("Firewall Raw ACE Count: " + str(len(ace_raw)))

prev_rule_id = '0'
c = 0
with open('rules.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    for i in ace_raw:
        raw_rule_full = []
        #extract the rule-id
        rule_id = re.findall('rule-id\s\d+', i)[0].split()[1]
        if rule_id == prev_rule_id:
            prev_rule_id = rule_id
            continue
        prev_rule_id = rule_id
        raw_rule_full = [elem for elem in ace_raw if rule_id in elem]

        rule_name = re.search('RULE:\s(.+)', [elem for elem in raw_rule_full if 'RULE:' in elem][0])[1]
        try:
            rule_action = [elem for elem in raw_rule_full if 'advanced' in elem][0].split()[3]
        except:
            #the rule is probably incomplete so ignore it
            continue
        c += 1

        if c == 1:
            writer.writerow(['Number','Name','Source Zone/Interface','Source','Destination Zone/Interface','Destination','Source Service','Destination Service','Action'])

        rule_matcher = re.compile("""advanced\s\w+\s(?P<proto>object-group\s\S+|\w+|\d+)\s
            (?P<src_ifc>ifc\s\w+)?\s?
            (?P<src>any|host\s\S+|object\s\S+|object-group\s\S+|(\d{1,3}\.?){4}\s(\d{1,3}\.?){4})\s
            (?P<src_service>eq\s\S+|object\s\S+|object-group\s\S+|range\s\d+\s\d+)?
            (?P<dest_ifc>ifc\s\w+)?\s?
            (?P<dest>any|host\s\S+|object\s\S+|object-group\s\S+|(\d{1,3}\.?){4}\s(\d{1,3}\.?){4})\s
            (?P<dest_service>eq\s\S+|object\s\S+|object-group\s\S+|range\s\d+\s\d+)?
            """, re.VERBOSE)

        l_rule_sifc = []
        l_rule_difc = []
        l_rule_src = []
        l_rule_dest = []
        l_rule_ssvc = []
        l_rule_dsvc = []

        for elem in raw_rule_full:
            if 'advanced' in elem:
                rule_matched = rule_matcher.search(elem)

                # protocol
                rule_proto = rule_matched.group('proto')
                if 'object' in rule_proto:
                    rule_proto = rule_proto.split()[1]

                # interfaces
                if not rule_matched.group('src_ifc'):
                    rule_sifc = 'ANY'
                else:
                    rule_sifc = str(rule_matched.group('src_ifc')).split()[1]

                if not rule_matched.group('dest_ifc'):
                    rule_difc = 'ANY'
                else:
                    rule_difc = str(rule_matched.group('dest_ifc')).split()[1]

                l_rule_sifc.append(rule_sifc)
                l_rule_difc.append(rule_difc)

                # service
                if not rule_matched.group('src_service'):
                    rule_ssvc = 'ANY'
                else:
                    rule_ssvc = rule_matched.group('src_service')

                # is this actually a service or not
                # (?P<src_service>eq\s\S+|object\s\S+|object-group\s\S+|range\s\d+\s\d+)?
                is_ssvc = False
                if 'ANY' in rule_ssvc:
                    is_ssvc = True
                    pass
                elif any(i in rule_ssvc for i in ['eq', 'range']):
                    is_ssvc = True
                else:
                    i = rule_ssvc.split()[1]
                    if len([elem for elem in object_group_network if i in elem]) > 0:
                        is_ssvc = False
                    elif len([elem for elem in object_network if i in elem]) > 0:
                        is_ssvc = False
                    else:
                        is_ssvc = True

                if not is_ssvc:
                    # group order below
                    # proto, src_inf, src, src_svc, dest_inf, dest, dest_svc
                    rule_ssvc = 'ANY'

                if any(i in rule_ssvc for i in ['object', 'eq']):
                    rule_ssvc = rule_ssvc.split()[1]

                if 'range' in rule_ssvc:
                    rule_ssvc = rule_ssvc.split()[1] + '-' + rule_ssvc.split()[2]

                l_rule_ssvc.append(rule_ssvc + '/' + rule_proto)

                if not is_ssvc:
                    if not rule_matched.group('dest'):
                         rule_dsvc = 'ANY'
                    else:
                        rule_dsvc = rule_matched.group('dest')
                else:
                    if not rule_matched.group('dest_service'):
                        rule_dsvc = 'ANY'
                    else:
                        rule_dsvc = rule_matched.group('dest_service')

                if any(i in rule_dsvc for i in ['object', 'eq']):
                    rule_dsvc = rule_dsvc.split()[1]

                if 'range' in rule_dsvc:
                    rule_ssvc = rule_dsvc.split()[1] + '-' + rule_dsvc.split()[2]

                l_rule_dsvc.append(rule_dsvc + '/' + rule_proto)

                # src
                rule_src = rule_matched.group('src')
                if any(i in rule_src for i in ['object', 'host']):
                    rule_src = rule_src.split()[1]
                elif re.match('(?:\d{1,3}\.?){4}\s(?:\d{1,3}\.?){4}', rule_src):
                    rule_src = ipaddress.IPv4Network(rule_src.split()[0] + '/' + rule_src.split()[1]).exploded

                # the rule name might be dynamic so we will explode it if it is so
                if 'FMC_INLINE_src' in rule_src:
                    rule_src = '\n'.join([elem[2] for elem in object_group_network if rule_src in elem])

                l_rule_src.append(rule_src)

                # dest
                if not is_ssvc:
                    rule_dest = rule_matched.group('src_service')
                else:
                    rule_dest = rule_matched.group('dest')
                if any(i in rule_dest for i in ['object', 'host']):
                    rule_dest = rule_dest.split()[1]
                elif re.match('(?:\d{1,3}\.?){4}\s(?:\d{1,3}\.?){4}', rule_dest):
                    rule_dest = ipaddress.IPv4Network(rule_dest.split()[0] + '/' + rule_dest.split()[1]).exploded

                # the rule name might be dynamic so we will explode it if it is so
                if 'FMC_INLINE_dst' in rule_dest:
                    rule_dest = '\n'.join([elem[2] for elem in object_group_network if rule_dest in elem])

                l_rule_dest.append(rule_dest)

                if is_ssvc:
                    print(rule_name)


        s_rule_sifc = '\n'.join(list(set(l_rule_sifc)))
        s_rule_src = '\n'.join(list(set(l_rule_src)))
        s_rule_difc = '\n'.join(list(set(l_rule_difc)))
        s_rule_dest = '\n'.join(list(set(l_rule_dest)))
        s_rule_ssvc = '\n'.join(list(set(l_rule_ssvc)))
        s_rule_dsvc = '\n'.join(list(set(l_rule_dsvc)))

        #print(str(c) + ' : ' + rule_id + ' |Name: ' + rule_name + '\n |src zone: ' + s_rule_sifc + '\n |src: ' + s_rule_src + '\n |src svc: ' + s_rule_ssvc + '\n |dest zone: ' + s_rule_difc + '\n |dest: ' + s_rule_dest + '\n |dest svc: ' + s_rule_dsvc + '\n |action: ' + rule_action)

        writer.writerow([str(c), rule_name, s_rule_sifc, s_rule_src, s_rule_difc, s_rule_dest, s_rule_ssvc, s_rule_dsvc, rule_action])
