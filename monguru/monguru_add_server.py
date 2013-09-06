#!/usr/bin/env python

import sys
import subprocess
import json
import getpass
import socket
import random
import string
import traceback
import os

sys.path.append('/tmp/monguru')

import requests
sys.stdin = open('/dev/tty')

MONGURU_BASE_URL="https://mongu.ru/"
YES_NO = ['Y', 'N']
PROCESS_TO_CHECK = ['httpd', 'apache', 'apache2', 'nginx', 'newrelic',
        'php5-fpm', 'php-fpm', 'sshd', 'exim4', 'cron', 'crond',
        'rsyslogd', 'syslog', 'syslogd', 'postgres', 'mysqld',
        'memcached', 'mongod', 'redis-server', 'node', 'nodejs']

SNMP_CHECK_PROCESS = 'check_snmp_proc_name!%s!%s!%s'

SERVICES = {
    'LOAD': {
                'use': 'monguru-generic-service',
                'host_name': '',
                'service_description': 'LOAD',
                'check_command': 'check_snmp_load!%s!%s!1.0,2.0,3.0!3.0,4.0,5.0'
                },

    'DISK': {
                'use': 'monguru-generic-service',
                'host_name': '',
                'service_description': 'DISK',
                'check_command': 'check_snmp_disk!%s!%s!/$!80%%!90%%'
                },
    'MEMORY': {
                'use': 'monguru-generic-service',
                'host_name': '',
                'service_description': 'MEMORY',
                'check_command': 'check_snmp_mem!%s!%s!80%%,30%%!90%%,50%%'
                },

    'CPU': {
                'use': 'monguru-generic-service',
                'host_name': '',
                'service_description': 'CPU',
                'check_command': 'check_snmp_cpu!%s!%s!90%%!99%%'
                },
}

def find_my_ip():
    ip = requests.get('http://icanhazip.com').text.replace('\n', '')
    fqdn = socket.getfqdn(ip)
    if ip != fqdn and ip in socket.gethostbyaddr(fqdn):
        return fqdn
    return ip

def query_custom_answers(question, answers, default=None):
    prompt_bits = []
    answer_from_valid_choice = {
        # <valid-choice>: <answer-without-&>
    }
    clean_answers = []
    for answer in answers:
        if '&' in answer and not answer.index('&') == len(answer)-1:
            head, sep, tail = answer.partition('&')
            prompt_bits.append(head.lower()+tail.lower().capitalize())
            clean_answer = head+tail
            shortcut = tail[0].lower()
        else:
            prompt_bits.append(answer.lower())
            clean_answer = answer
            shortcut = None
        if default is not None and clean_answer.lower() == default.lower():
            prompt_bits[-1] += " (default)"
        answer_from_valid_choice[clean_answer.lower()] = clean_answer
        if shortcut:
            answer_from_valid_choice[shortcut] = clean_answer
        clean_answers.append(clean_answer.lower())

    prompt = " [%s] " % ", ".join(prompt_bits)
    leader = question + prompt
    if len(leader) + max(len(c) for c in answer_from_valid_choice.keys() + ['']) > 78:
        leader = question + '\n' + prompt.lstrip()
    leader = leader.lstrip()

    valid_choices = answer_from_valid_choice.keys()
    if clean_answers:
        admonishment = "*** Please respond with '%s' or '%s'. ***" \
                       % ("', '".join(clean_answers[:-1]), clean_answers[-1])

    while 1:
        sys.stdout.write(leader)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return default
        elif choice in answer_from_valid_choice:
            return answer_from_valid_choice[choice]
        else:
            sys.stdout.write("\n"+admonishment+"\n\n\n")
def configure_snmpd(snmp_login, snmp_password):
    snmp_files = ['/var/lib/snmp/snmpd.conf']
    snmp_config_file = '/etc/snmp/snmpd.conf'

    f_snmp_config_file = open(snmp_config_file, 'a')
    f_snmp_config_file.write('rouser    %s  priv -V systemonly\n' % snmp_login)

    for f in snmp_files:
        if os.path.isfile(f):
            os.system('/etc/init.d/snmpd stop')
            cfile = open(f, 'a')
            cfile.write('createUser %s SHA1 "%s" AES\n' % (
                snmp_login, snmp_password))
            cfile.write('rouser %s\n' % snmp_login)
            cfile.close()
            os.system('/etc/init.d/snmpd start')
            return True
    return False


def connected_ports(ip, port):
    print "-Testing port connetion from the internet to %s:%s..." % (ip, port),
    data = {
            'remoteHost': ip,
            'start_port': port,
            'end_port': port,
            'scan_type': 'connect',
            'normalScan': 'Yes',
            }

    output = requests.post('http://www.ipfingerprints.com/scripts/getPortsInfo.php', data=data)
    if 'open ' in output.text:
        print "port is open."
        return True
    print "port is closed."
    return False


def create_instance(username, password, auth_cookie):
    snmp_login = ''.join(random.choice(string.ascii_lowercase +
        string.digits) for x in range(16))
    snmp_password = ''.join(random.choice(string.ascii_letters +
        string.digits) for x in range(16))
    data = {
                'friendly_name': 'My First Instance',
                'fqdn': '',
                'userslist': '%s:%s' % (username, password),
                'snmp_auth_cred': '%s:%s' % (snmp_login, snmp_password)
            }
    r = requests.post(MONGURU_BASE_URL+'/nagiosv3/create_instance/', data=data, cookies=auth_cookie, verify=False)
    return r.json()


def get_config_cursor(instance_key, auth_cookie):
    r = requests.get(MONGURU_BASE_URL+'/nagiosv3/config/cursor/get/%s' %
            instance_key, cookies=auth_cookie, verify=False)
    return r.json()['cursor']

def commit_config_cursor(instance_key, cursor, auth_cookie):
    r = requests.get(MONGURU_BASE_URL+'/nagiosv3/config/cursor/commit/%s/%s' %
            (instance_key, cursor), cookies=auth_cookie, verify=False)
    return r.json()


def add_server(instance_key, config_cursor, req, auth_cookie):
    r = requests.put(MONGURU_BASE_URL+'/nagiosv3/config/host/add/%s/%s/' % (
        instance_key, config_cursor), data=json.dumps(req['hosts']), cookies=auth_cookie, verify=False)

    r = requests.put(MONGURU_BASE_URL+'/nagiosv3/config/service/add/%s/%s/' % (
        instance_key, config_cursor), data=json.dumps(req['services']), cookies=auth_cookie, verify=False)
    return r.json()

def ping_me(address):
    print "-Trying to ping address %s..." % address,
    r = requests.get(MONGURU_BASE_URL+'/utils/ping_me/%s/' % address, verify=False)
    print "done."
    return r.json()['ping']

def snmp_me(address, login, password):
    print "-Trying to connect to snmp daemon...",
    r = requests.get(MONGURU_BASE_URL+'/utils/snmp_me/%s/%s/%s/' % (address, login, password), verify=False)
    print "done."
    return r.json()['snmp']


def get_infos():

    print "-Trying to get server ip address...",
    my_ip = find_my_ip()
    print "done."
    correct_found_ip = query_custom_answers(
        '-I found the ip %s as this server address, is it correct ?' % my_ip, YES_NO)
    if correct_found_ip == YES_NO[1]:
        my_ip = raw_input('-Please enter the host (FQDN) or IP to use as address: ')
    if not ping_me(my_ip):
        print "*** ERROR ***: Sorry, MonGuru server cannot ping your address %s. Is ICMP reply (type 0) open on firewall ?" % my_ip
        sys.exit(3)

    hostname = socket.gethostname()
    correct_found_hostname = query_custom_answers(
            '-Would you like to use the found hostname (%s)  to identify this host in Nagios ?' % my_ip, YES_NO)
    if correct_found_hostname == YES_NO[1]:
            hostname = raw_input('-Please enter the host name to identify this host in Nagios: ')

    process_list = subprocess.Popen(['ps', '-Aofname'],
            stdout=subprocess.PIPE).communicate()[0].splitlines()


    email = raw_input('''Enter the MonGuru login (email), if you don't have one, create at %s: ''' % MONGURU_BASE_URL)
    password = getpass.getpass('Password: ')
    print "-Authenticating...",
    new = False
    url = MONGURU_BASE_URL+'/login/'
    r = requests.get(url, verify=False)
    print "done."
    csrftoken = r.cookies['csrftoken']
    payload = {'username': email, 'password': password, 'csrfmiddlewaretoken': csrftoken}
    cookies = {'csrftoken':csrftoken}
    headers = {'Referer': url}
    r = requests.post(url, cookies=cookies, data=payload, headers=headers, verify=False)
    cookies_list = r.request.headers['Cookie'].split()
    session_id = ''
    for c in cookies_list:
        if c.startswith('sessionid='):
            session_id = c.split('=')[1].replace(';', '')
            break
    cookies['sessionid'] = session_id
    print "-Searching for instances...",
    instances = requests.get(MONGURU_BASE_URL+'/nagiosv3/list_instances/', cookies=cookies, verify=False).json()
    print "done."


    #TODO: ask which instance to use
    if instances:
        instance = instances[0]
    else:
        print "-No instance found. Creating one...",
        new = True
        instance = create_instance(email, password, cookies)
        print "done."

    snmp_login = instance['snmp_auth_cred'].split(':')[0]
    snmp_password = instance['snmp_auth_cred'].split(':')[1]
    if not snmp_login or not snmp_password:
        print "*** ERROR ***: Compatibility only new Nagios instances will work with this script..."
        print "Trying to backup your current instance config files, and then removing it"
        print "You can sent an e-mail to help@mongu.ru"
        print "Finished with ERROR!"
        sys.exit(3)

    if not configure_snmpd(snmp_login, snmp_password):
        print "*** ERROR ***: Sorry, Cannot configure snmpd..."
        sys.exit(3)

    if not snmp_me(my_ip, snmp_login, snmp_password):
        print "*** ERROR ***: Sorry, MonGuru server cannot connect via snmp to address %s. Is udp port 161 (snmp) open on firewall ?" % my_ip
        sys.exit(3)

    for service in SERVICES:
        c_command = SERVICES[service]['check_command'] % (snmp_login, snmp_password)
        SERVICES[service]['check_command'] = c_command
        SERVICES[service]['host_name'] = hostname

    for process in PROCESS_TO_CHECK:
        if process in process_list:
            print '-Configuring process check for %s...' % process,
            c_command = SNMP_CHECK_PROCESS % (snmp_login, snmp_password, process)
            SERVICES['PROCESS-%s' % process] = {}
            SERVICES['PROCESS-%s' % process]['use'] = 'monguru-generic-service'
            SERVICES['PROCESS-%s' % process]['check_command'] = c_command
            SERVICES['PROCESS-%s' % process]['host_name'] = hostname
            SERVICES['PROCESS-%s' % process]['service_description'
                    ] = 'PROCESS-%s' % process
            print 'done.'

    port_https = connected_ports(my_ip, '443')
    port_http = connected_ports(my_ip, '80')


    if port_https:
        SERVICES['HTTPS'] = {}
        SERVICES['HTTPS']['use'] = 'monguru-generic-service'
        SERVICES['HTTPS']['check_command'] = 'check_https_vhost!%s!/' % my_ip
        SERVICES['HTTPS']['host_name'] = hostname
        SERVICES['HTTPS']['service_description'] = 'HTTPS'

    if port_http:
        SERVICES['HTTP'] = {}
        SERVICES['HTTP']['use'] = 'monguru-generic-service'
        SERVICES['HTTP']['check_command'] = 'check_http_vhost!%s!/' % my_ip
        SERVICES['HTTP']['host_name'] = hostname
        SERVICES['HTTP']['service_description'] = 'HTTP'

    SERVICES['PING'] = {
                'use': 'monguru-generic-service',
                'host_name': hostname,
                'service_description': 'PING',
                'check_command': 'check_ping!5000.0,95%!10000.0,96%'
                }


    hosts= {
                my_ip:
               {
               'use': 'monguru-generic-host',
               'host_name': hostname,
               'address': my_ip,
               }
           }

    req = {
            'hosts': hosts,
            'services': SERVICES,
          }


    print "-Adding this server to Nagios...",
    config_cursor = get_config_cursor(instance['instance_key'], cookies)
    add_server(instance['instance_key'], config_cursor, req, cookies)
    output = commit_config_cursor(instance['instance_key'], config_cursor, cookies)

    if output['status'] > 299:
        print "ERROR."
        print '*** Cannot do it ***, please contact help@mongu.ru:\n %s' % output['msg']
        sys.exit(output['status'])
    print "done."
    print '-Everything was smooth and we added your server to the Nagios instance %s.' % instance['instance_key']
    if new:
        print '-Use your email as login (%s)' % email
    print '*** Please *** visit the url %s to see it' % instance['instance_url']
    print "-Don't know Nagios ? Visit http://wiki.mongu.ru/wiki/Basic_Nagios"
if __name__ == '__main__':
    try:
        get_infos()
    except ValueError:
        print traceback.format_exc()
        print "*** ERROR ***: I'm sorry, but we found an error processing your request, unfortunately it"
        print "is a generic error, and I'm not able to specify it for you."
        print "Please, contact help@mongu.ru  and paste the arror above."
