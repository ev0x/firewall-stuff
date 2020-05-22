#!/usr/bin/env python3
import string
import re
import mmap
import csv
import ipaddress

with open('config.txt', 'r') as f:
    data = f.read()

o_name = re.findall('name\s[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}\s.+', data)
o_service = re.findall('object\sservice\s.+\n(?:\s.+\n?)+', data)
o_network = re.findall('object\snetwork\s.+\n(?:\s.+\n?)+', data)
og_service = re.findall('object-group\sservice\s.+\n(?:\s.+\n?)+', data)
og_network = re.findall('object-group\snetwork\s.+\n(?:\s.+\n?)+', data)
hostname = re.findall('hostname\s.+', data)
print("Firewall Host: " + hostname[0].split(' ')[1])
print("names: " + str(len(o_name)))
print("object service: " + str(len(o_service)))
print("object network: " + str(len(o_network)))
print("object-group service: " + str(len(og_service)))
print("object-group network: " + str(len(og_network)))

vlan_map = {
    '11': 'A',
    '311': 'B',
    '511': 'C'
}

# pull the ipam ip data into a dict
with open('ipam_extract.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data_ipam = {k:v for k, v in reader}
print("IPAM Entries: " + str(len(data_ipam)))

# pull the ipam subnet data into a dict
with open('ipam_subnets.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data_subnets = {k:v for k, v in reader}
print("IPAM Subnets: " + str(len(data_subnets)))

# pull the routes from the firewall
with open('routes.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data_routes = {}
    for k,v in reader:
        data_routes[k] = vlan_map.get(v, 'outside')
print("Routes: " + str(len(data_routes)))
print("\n")

#object network
with open('object_network.csv', 'w', newline='') as csvfile:
    print('Processing... object network')
    writer = csv.writer(csvfile)
    objNetwork = {} # create this dict for later
    lofl = []
    lofl.append(['Name','Host','Description','Interface','IPAM'])
    for i in o_network:
        clean = list(filter(None, [x.strip() for x in i.split('\n')]))
        name = clean[0].split(' ')[2]
        desc = ""
        try:
            if re.match('description\s.+', clean[1]):
                desc = clean[1].split('description ')[1]
            if re.match('description\s.+', clean[2]):
                desc = clean[2].split('description ')[1]
        except:
            pass

        for r in clean:
            ipam = ""
            route = "outside" #default route
            if re.match('host\s.+', r):
                for k,v in data_routes.items():
                    host = str(r.split(' ')[1])
                    if ipaddress.ip_address(host) in ipaddress.ip_network(k):
                        route = v.split(' ')[0]

                lofl.append([name, r.split(' ')[1], desc, route])
                objNetwork[name] = r.split(' ')[1]

                if r.split(' ')[1] in data_ipam:
                    ipam = data_ipam[r.split(' ')[1]]
                if ipam == "":
                    # perform a substr dict value lookup
                    try:
                        ipam = [k + '|' + v for k,v in data_ipam.items() if r.split(' ')[1].lower() in v.lower()][0]
                    except:
                        pass
            if re.match('subnet\s.+', r):
                #extract the subnet
                exploded = ipaddress.IPv4Network(r.split(' ')[1] + '/' + r.split(' ')[2]).exploded
                for k,v in data_routes.items():
                    host = str(exploded.split('/')[0])
                    if ipaddress.ip_address(host) in ipaddress.ip_network(k):
                        route = v.split(' ')[0]

                lofl.append([name, exploded, desc, route])
                objNetwork[name] = exploded

                if exploded in data_subnets:
                    ipam = data_subnets[exploded]

            if re.match('range\s.+', r):
                for k,v in data_routes.items():
                    # get the first host
                    host = str(r.split(' ')[1])
                    if ipaddress.ip_address(host) in ipaddress.ip_network(k):
                        route = v.split(' ')[0]

                hostrange = r.split(' ')[1] + '-' + r.split(' ')[2].split('.')[3]
                lofl.append([name, hostrange, desc, route, ipam])
                objNetwork[name] = hostrange

    writer.writerows(lofl)

#object-group service
with open('object-group_services.csv', 'w', newline='') as csvfile:
    print('Processing... object-group services')
    writer = csv.writer(csvfile)
    lofl = []
    lofl.append(['Name', 'Type', 'Service', 'Description', 'Count'])
    for i in og_service:
        clean = list(filter(None, [x.strip() for x in i.split('\n')]))
        name = clean[0].split(' ')[2]
        try:
            type = clean[0].split(' ')[3]
        except:
            type = "tcp-udp"
        desc = ""
        c_port = 0
        c_range = 0
        nothing = ""
        try:
            if re.match('description\s.+', clean[1]):
                desc = clean[1].split('description ')[1]
        except:
            pass

        for r in clean:
            if re.match('port-object\seq.+', r): # port-object eq x
                lofl.append([name, type, r.split(' ')[2], desc, nothing])
                c_port += 1
            if re.match('port-object\srange.+', r): # port-object range x x
                lofl.append([name, type, r.split(' ')[2] + "-" + r.split(' ')[3], desc, nothing])
                c_range += 1

        for i in range(len(lofl)):
            if i == 1: pass
            if lofl[i][0] == name:
                lofl[i][4] = str(c_port) + ' ports | ' + str(c_range) + ' ranges'

        c_port = 0
        c_range = 0

    writer.writerows(lofl)

#object-group network
#we will read the object network back in so we can use it to map the objects
with open('object_network.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    object_network = [i for i in reader]

with open('object-group_network.csv', 'w', newline='') as csvfile:
    print('Processing... object-group network')
    writer = csv.writer(csvfile)
    lofl = []
    lofl.append(['Name', 'Type', 'Network', 'Interface', 'Description', 'Notes', 'IPAM', 'Subnet'])
    nothing = ""
    c_host = 0
    c_network = 0
    c_object = 0
    for i in og_network:
        clean = list(filter(None, [x.strip() for x in i.split('\n')]))
        name = clean[0].split(' ')[2]
        esc = ""
        try:
            if re.match('description\s.+', clean[1]):
                desc = clean[1].split('description ')[1]
        except:
            pass
        for r in clean:
            ipam = ""
            subnet = ""
            route = "outside" #default
            if re.match('network-object\shost.+', r): # network-object host x
                if r.split(' ')[2] in data_ipam:
                    ipam = data_ipam[r.split(' ')[2]]
                if ipam == "":
                    # perform a substr dict value lookup
                    if len(sub_k) > 0:
                        ipam = [k + '|' + v
                        for k,v in data_ipam.items() if r.split(' ')[2].lower() in v.lower()][0]
                for k,v in data_subnets.items():
                    host = str(r.split(' ')[2])
                    try:
                        if ipaddress.ip_address(host) in ipaddress.ip_network(k):
                            subnet = v
                    except ValueError:
                        pass
                #find the route
                for k,v in data_routes.items():
                    host = str(r.split(' ')[2])
                    try:
                        if ipaddress.ip_address(host) in ipaddress.ip_network(k):
                            route = v.split(' ')[0]
                    except ValueError:
                        pass

                lofl.append([name, 'host', r.split(' ')[2], route, desc, nothing, ipam, subnet])
                c_host += 1
            if re.match('network-object\s[0-9\.\s]+', r): # network-object x.x.x.x x.x.x.x
                try:
                    net = ipaddress.ip_network(r.split(' ')[1] + '/' + r.split(' ')[2], strict=False)
                except ValueError:
                    pass
                if net in data_subnets:
                    ipam = data_subnets[net]

                # find the route
                for k,v in data_routes.items():
                    host = str(r.split(' ')[1])
                    if ipaddress.ip_address(host) in ipaddress.ip_network(k):
                        route = v.split(' ')[0]

                lofl.append([name, 'network', net, route, desc, nothing, ipam])
                c_network += 1
            if re.match('network-object\sobject.+', r): # network-object object x
                addr = ""
                if r.split(' ')[2] in [elem for elem in object_network if r.split(' ')[2] in elem][0]:
                    addr = [elem for elem in object_network if r.split(' ')[2] in elem][0][1]

                if addr in data_ipam:
                    ipam = data_ipam[addr]

                # find the route
                for k,v in data_routes.items():
                    host = str(addr)
                    try:
                        if ipaddress.ip_address(host) in ipaddress.ip_network(k):
                            route = v.split(' ')[0]
                    except:
                        pass

                lofl.append([name, 'object', r.split(' ')[2] + ' [' + addr + ']', route, desc, nothing, ipam])
                c_object += 1
            if re.match('group-object\s.+', r): # group-object ABC-123
                lofl.append([name, 'group-object', r.split(' ')[1], route, desc, nothing, ipam])

        for i in range(len(lofl)):
            if i == 1: pass
            if lofl[i][0] == name:
                lofl[i][5] = str(c_host) + ' hosts | ' + str(c_network) + ' networks | ' + str(c_object) + ' objects'

        c_host = 0
        c_network = 0
        c_object = 0

    writer.writerows(lofl)
