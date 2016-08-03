#!/usr/bin/python
# -*- coding: utf-8 -*-

import colorlog
import sys
import json
import pexpect
from collections import OrderedDict

# LOG_FLAG = True
LOG_FLAG = False
VRRP_STS_INFO = ["MASTER", "BACKUP"]

##############################################################################
# ColorLog
##############################################################################
class HAProxy(object):
    log = colorlog.ColorLog(LOG_FLAG)

    ##########################################################################
    #
    ##########################################################################
    PROMPT_ALL = ['# ', '>>> ', '> ', '\$ ', '\# ']
    PROMPT_ROOT = ['# ', ':~# ']
    PROMPT_PUBLIC = ['\$ ', '\~$ ']

    LOG_OFF = False
    LOG_ON = True

    SSH_AUTH_OFF = False
    SSH_AUTH_ON = True

    # config information
    scp_config_path = ""
    scp_common_path = ""
    scp_pw = ""

    keepalived_pkg =""
    haproxy_pkg =""

    virtual_ip = ""
    keepalive_interface = ""
    vrrp_interface = ""

    # monitoring information
    m_haproxy_ver = "-"
    m_haproxy_proc = "-"
    m_haproxy_pid = "-"
    m_haproxy_status = "-"
    m_haproxy_ha_status = "-"

    m_keepalived_ver = "-"
    m_keepalived_proc = "-"
    m_keepalived_pid = "-"

    m_virtual_ip = "-"
    m_vrrp_tcp_dump = "-"

    ##########################################################################
    #
    ##########################################################################
    def __init__(self, a_name="", a_ip="", a_ssh_id="", a_ssh_pw="", a_root_pw="", a_status=""):
        self.name = a_name
        self.ip = a_ip
        self.ssh_id = a_ssh_id
        self.ssh_pw = a_ssh_pw
        self.root_pw = a_root_pw
        self.status = a_status

    ##########################################################################
    #
    ##########################################################################
    def load_config_file(self, file_name, proxy_name):
        try:
            with open(file_name, 'r') as f:
                json_input = f.read()
        except IOError as ioerr:
            self.log.printr("File error : " + str(ioerr))
            self.log.printe()
            sys.exit(0)
        try:
            decoded = json.loads(json_input)
            self.name = decoded[proxy_name]['name']
            self.ip = decoded[proxy_name]['ip']
            self.ssh_id = decoded[proxy_name]['ssh_id']
            self.ssh_pw = decoded[proxy_name]['ssh_pw']
            self.root_pw = decoded[proxy_name]['root_pw']

            self.scp_config_path = decoded['scp']['config_path']
            self.scp_common_path = decoded['scp']['common_path']
            self.scp_pw = decoded['scp']['pw']

            self.haproxy_pkg = decoded['src_pkg']['haproxy']
            self.keepalived_pkg = decoded['src_pkg']['keepalived']

            self.virtual_ip = decoded['keepalive']['virtual_ip']
            self.keepalive_interface = decoded['keepalive']['keepalive_interface']
            self.vrrp_interface = decoded['keepalive']['vrrp_interface']

        except (ValueError, KeyError, TypeError) as err:
            self.log.printr("JSON format error :: %s" % str(err))
            self.log.printe()
            sys.exit(0)

    ##########################################################################
    #
    ##########################################################################
    def print_config_info(self):
        self.log.printg("+ HA Proxy information ")
        self.log.printg("  + host     = %s" % self.name)
        self.log.printg("  + ip       = %s" % self.ip)
        self.log.printg("  + ssh_id   = %s" % self.ssh_id)
        self.log.printg("  + ssh_pw   = %s" % self.ssh_pw)
        self.log.printg("  + root_pw  = %s" % self.root_pw)

        self.log.printg("")
        self.log.printg("+ SCP information (install system)")
        self.log.printg("  + scp_config_path = %s" % self.scp_config_path)
        self.log.printg("  + scp_common_path = %s" % self.scp_common_path)
        self.log.printg("  + scp_pw          = %s" % self.scp_pw)

        self.log.printg("")
        self.log.printg("+ keepalive information")
        self.log.printg("  + virtual_ip          = %s" % self.virtual_ip)
        self.log.printg("  + keepalive_interface = %s" % self.keepalive_interface)
        self.log.printg("  + vrrp_interface      = %s" % self.vrrp_interface)

        self.log.printg("")
        self.log.printg("+ package information")
        self.log.printg("  + haproxy    = %s" % self.haproxy_pkg)
        self.log.printg("  + keepalived = %s" % self.keepalived_pkg)

    ##########################################################################
    #
    ##########################################################################
    def ssh_connect(self, log_flag):
        ssh_newkey = 'Are you sure you want to continue connecting'
        ssh_conn = 'ssh ' + self.ssh_id + '@' + self.ip

        try:
            child = pexpect.spawn(ssh_conn)
            ret = child.expect([pexpect.TIMEOUT, ssh_newkey, '[P|p]assword:'])
        except Exception as err:
            self.log.printr("SSH Connect error :: %s" % str(err))
            self.log.printe()
            sys.exit(0)

        # Resonse Conditions....
        if ret == 0:
            self.log.printr("SSH connection failed on login ==> host=%s, ip=%s, ssh_id=%s, ssh_pw=%s, root_pw=%s"
                            % (self.name, self.ip, self.ssh_id, self.ssh_pw, self.root_pw))
            sys.exit(0)

        if ret == 1:
            child.sendline('yes')
            ret = child.expect([pexpect.TIMEOUT, '[P|p]assword'])

        if ret == 0:
            self.log.printr("SSH connection failed on login ==> host=%s, ip=%s, ssh_id=%s, ssh_pw=%s, root_pw=%s"
                            % (self.name, self.ip, self.ssh_id, self.ssh_pw, self.root_pw))
            sys.exit(0)

        try:
            child.sendline(self.ssh_pw)
            child.expect(self.PROMPT_ALL)
        except Exception as err:
            self.log.printr("SSH Connect error :: %s" % str(err))
            self.log.printe()
            sys.exit(0)

        if log_flag is True:
            self.log.printb("ssh connection is success : %s(%s)" % (self.name, self.ip))

        return child

    ##############################################################################
    # ssh_command_prompt
    ##############################################################################
    def ssh_command_prompt(self, child, remote_command, prompt, print_flag, log_flag):
        self.log.printb("[REMOTE COMMAND] = %s" % remote_command)

        ret = child.sendline(remote_command)
        child.expect(prompt)
        # print("[ORG]= %s" % child.before)

        result = child.before.split('root')
        if log_flag is True:
            if print_flag == self.LOG_ON:
                print result[0]
        return child.before

    ##############################################################################
    # ssh_command_public
    ##############################################################################
    def ssh_command_public(self, child, remote_command, prompt, print_flag, log_flag):
        self.log.printb("[REMOTE COMMAND] = %s" % remote_command)

        ret = child.sendline(remote_command)
        child.expect(prompt)
        # print("[ORG]= %s" % child.before)

        result = child.before.split(str(self.ssh_id))
        if log_flag is True:
            if print_flag == self.LOG_ON:
                print result[0]
        return child.before

    ##############################################################################
    # ssh_scp_command
    ##############################################################################
    def ssh_scp_command(self, child, remote_command, ssh_auth, prompt, log_flag):
        self.log.printb("[REMOTE COMMAND] = %s" % remote_command)
        child.sendline(remote_command)
        if ssh_auth == self.SSH_AUTH_ON:
            child.expect([pexpect.TIMEOUT,
                          'Are you sure you want to continue connecting',
                          '[P|p]assword:'])
            child.sendline('yes')
        child.expect([pexpect.TIMEOUT, '[P|p]assword:'])
        child.sendline(self.scp_pw)
        child.expect(prompt)
        result = child.before.split('root')
        if log_flag is True:
            print result[0]

    ##############################################################################
    # ssh_haproxy_config
    ##############################################################################
    def ssh_haproxy_config(self, child, log_flag):
        remote_command = "sudo su -"
        self.log.printb("[REMOTE COMMAND] = %s" % remote_command)
        child.sendline(remote_command)
        child.expect("password for %s: " % self.ssh_id)
        child.sendline(self.root_pw)
        child.expect(self.PROMPT_ROOT)

        remote_command = "cat /etc/sysctl.conf | grep net.ipv4.ip_nonlocal_bind"
        self.log.printb("[REMOTE COMMAND] = %s" % remote_command)
        child.sendline(remote_command)
        child.expect(self.PROMPT_ROOT)
        result = child.before
        list_result = result.split('\r\n')

        if list_result[1].find("net") > 0:
            pass
        else:
            remote_command = "echo net.ipv4.ip_nonlocal_bind=1 >> /etc/sysctl.conf"
            self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "sysctl -p"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "cat /proc/sys/net/ipv4/ip_nonlocal_bind"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "mkdir -p /var/log/haproxy"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "chown syslog:syslog /var/log/haproxy"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "scp" + " " + self.scp_common_path + "/rsyslog_haproxy.conf" \
                         + " " + "/etc/rsyslog.d/haproxy.conf"
        self.ssh_scp_command(child, remote_command, self.SSH_AUTH_ON, self.PROMPT_ROOT, log_flag)

        remote_command = "scp" + " " + self.scp_config_path + "/hosts." + self.name + " " + "/etc/hosts"
        self.ssh_scp_command(child, remote_command, self.SSH_AUTH_OFF, self.PROMPT_ROOT, log_flag)

    ##############################################################################
    # ssh_install_keepalived_daemon
    ##############################################################################
    def ssh_install_keepalived_daemon(self, child, log_flag):
        remote_command = "rm /var/lib/dpkg/lock"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "service keepalived stop"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "apt-get -y install keepalived"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "apt-get -y install libssl-dev"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "cd /usr/local/src"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "rm -rf keepalive*"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        # remote_command = "wget http://www.keepalived.org/software/keepalived-1.2.22.tar.gz"
        # self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "scp" + " " + self.scp_common_path +"/"+  self.keepalived_pkg + ".tar.gz ."
        self.ssh_scp_command(child, remote_command, self.SSH_AUTH_OFF, self.PROMPT_ROOT, log_flag)

        remote_command = "tar -xvf " +  self.keepalived_pkg + ".tar.gz"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_OFF, log_flag)

        remote_command = "cd "+  self.keepalived_pkg
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "./configure"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "make"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_OFF, log_flag)

        remote_command = "make install"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "mv -v /usr/sbin/keepalived /usr/sbin/keepalived.1.2.7"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "cp -v bin/keepalived /usr/sbin/keepalived"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "cp -v bin/genhash /usr/bin/"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "keepalived -v"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "scp" + " " + self.scp_config_path + "/keepalived_" + self.name + ".conf" \
                         + " " + "/etc/keepalived/keepalived.conf"
        self.ssh_scp_command(child, remote_command, self.SSH_AUTH_OFF, self.PROMPT_ROOT, log_flag)

        remote_command = "scp" + " " + self.scp_common_path + "/chk_haproxy.sh" \
                         + " " + "/etc/keepalived/chk_haproxy.sh"
        self.ssh_scp_command(child, remote_command, self.SSH_AUTH_OFF, self.PROMPT_ROOT, log_flag)

        remote_command = "scp" + " " + self.scp_common_path + "/vrrp.notify.sh" \
                         + " " + "/etc/keepalived/vrrp.notify.sh"
        self.ssh_scp_command(child, remote_command, self.SSH_AUTH_OFF, self.PROMPT_ROOT, log_flag)

        remote_command = "service keepalived restart"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "ps -aef | grep keepalived"
        result = self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_OFF, log_flag)
        if log_flag is True:
            print ("%s" % result)

    ##############################################################################
    # ssh_install_haproxy
    ##############################################################################
    def ssh_install_haproxy(self, child, log_flag):
        remote_command = "rm /var/lib/dpkg/lock"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "rm /etc/haproxy/haproxy.cfg"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "service haproxy stop"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "apt-get -y install haproxy"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "apt-get -y remove haproxy"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "perl -pi -e 's/ENABLED=0/ENABLED=1/g' /etc/default/haproxy"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "cd /usr/local/src"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "rm -rf haproxy*"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        # remote_command = "wget http://www.haproxy.org/download/1.6/src/haproxy-1.6.5.tar.gz"
        # self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "scp" + " " + self.scp_common_path +"/"+ self.haproxy_pkg + ".tar.gz ."
        self.ssh_scp_command(child, remote_command, self.SSH_AUTH_OFF, self.PROMPT_ROOT, log_flag)

        remote_command = "tar -xvf " + self.haproxy_pkg +".tar.gz"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_OFF, log_flag)

        remote_command = "cd " + self.haproxy_pkg
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "make TARGET=linux2628 CPU=native"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_OFF, log_flag)

        remote_command = "make install"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "scp" + " " + self.scp_common_path + "/haproxy_upstart_script" \
                         + " " + "/etc/init.d/haproxy"
        self.ssh_scp_command(child, remote_command, self.SSH_AUTH_OFF, self.PROMPT_ROOT, log_flag)

        remote_command = "rm /usr/sbin/haproxy"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "ln -s /usr/local/sbin/haproxy /usr/sbin/haproxy"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "haproxy -v"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "mkdir -p /etc/haproxy"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "scp" + " " + self.scp_common_path + "/haproxy.cfg" \
                         + " " + "/etc/haproxy/haproxy.cfg"
        self.ssh_scp_command(child, remote_command, self.SSH_AUTH_OFF, self.PROMPT_ROOT, log_flag)

        remote_command = "service haproxy restart"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "service haproxy status"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "ip addr list eth0"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        remote_command = "scp" + " " + self.scp_common_path + "/chk_onos_ins"+ " " + "/etc/haproxy/"
        self.ssh_scp_command(child, remote_command, self.SSH_AUTH_OFF, self.PROMPT_ROOT, log_flag)
        remote_command = "chmod +x /etc/haproxy/chk_onos_ins"
        self.ssh_scp_command(child, remote_command, self.SSH_AUTH_OFF, self.PROMPT_ROOT, log_flag)
        remote_command = "scp" + " " + self.scp_common_path + "/onos_proxy.json"+ " " + "/etc/haproxy/"
        self.ssh_scp_command(child, remote_command, self.SSH_AUTH_OFF, self.PROMPT_ROOT, log_flag)

    ##############################################################################
    # ssh_get_haproxy_status
    ##############################################################################
    def ssh_get_haproxy_status(self, child):
        remote_command = "cat /var/log/haproxy/vrrp.status"
        child.sendline(remote_command)
        child.expect(self.PROMPT_ALL)
        result = child.before.split('\r\n')
        self.status = result[1]
        if self.status not in VRRP_STS_INFO :
           self.status = "UNKNOWN"

        remote_command = "keepalived -v"
        child.sendline(remote_command)
        child.expect(self.PROMPT_ALL)
        result = child.before.split('\r\n')
        result = result[1].split(" ")
        self.m_keepalived_ver = str(result[1]).replace("v", "")

        remote_command = "haproxy -v"
        child.sendline(remote_command)
        child.expect(self.PROMPT_ALL)
        result = child.before.split('\r\n')
        result = result[1].split(" ")
        self.m_haproxy_ver = result[2]

    ##############################################################################
    # ssh_get_system_monitor
    ##############################################################################
    def ssh_get_system_monitor(self, child, log_flag):
        remote_command = "sudo su -"
        self.log.printb("[REMOTE COMMAND] = %s" % remote_command)
        child.sendline(remote_command)
        child.expect("password for %s: " % self.ssh_id)
        child.sendline(self.root_pw)
        child.expect(self.PROMPT_ROOT)

        log.printt(98, "# STEP 1. get haproxy version" + " " * 40)
        remote_command = "haproxy -v"
        result = self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)
        result = result.split("\r\n")
        result = result[1].split(" ")
        self.m_haproxy_ver = result[2]

        log.printg("")
        log.printt(98, "# STEP 2. get haproxy process info" + " " * 35)
        remote_command = "ps -aef | grep haproxy --color=never"
        results = self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)
        print ("%s" % results)

        pid = ""
        pid_cnt = 0
        results = results.split("\r\n")
        for result in results[1:len(results)-1]:
            if result.find("grep") == -1 and result.find("haproxy") >= 0:
                result = result.split(" ")
                result = list(OrderedDict.fromkeys(result))
                if "" in result:
                   result.remove("")

                pid += result[1]
                pid += ", "
                pid_cnt += 1

        if (pid_cnt >= 1):
            pid = pid[0:-2]
            self.m_haproxy_proc = "running"
            self.m_haproxy_pid = pid
        else:
            self.m_haproxy_proc = "not running"

        log.printg("")
        log.printt(98, "# STEP 3. get haproxy binding info" + " " * 35)
        remote_command = "netstat -anp | grep haproxy"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        log.printg("")
        log.printt(98, "# STEP 4. get haproxy status" + " " * 41)
        remote_command = "service haproxy status"
        result = self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        log.printg("")
        result = result.split("\r\n")
        result = result[1].strip(".").split(" ")
        if result[1].find("is") >= 0:
            self.m_haproxy_status = "running"
        else:
            self.m_haproxy_status = "not running"

        remote_command = "cat /var/log/haproxy/vrrp.status"
        result = self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)
        log.printg("")
        result = result.split("\r\n")

        if self.m_haproxy_status == "running":
            self.m_haproxy_ha_status = result[1]
        else:
            self.m_haproxy_ha_status = "-"

        log.printg("")
        log.printt(98, "# STEP 5. get keepalived version" + " " * 37)
        remote_command = "keepalived -v"
        result = self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        result = result.split('\r\n')
        result = result[1].split(" ")
        self.m_keepalived_ver = str(result[1]).replace("v", "")

        log.printg("")
        log.printt(98, "# STEP 6. get keepalived process info" + " " * 32)
        remote_command = "ps -aef | grep keepalived --color=never"
        results = self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)
        print ("%s" % results)

        pid = ""
        pid_cnt = 0
        results = results.split("\r\n")
        for result in results[1:len(results)-1]:
            if result.find("grep") == -1 and result.find("keepalived") >= 0:
                result = result.split(" ")
                result = list(OrderedDict.fromkeys(result))
                if "" in result:
                   result.remove("")

                pid += result[1]
                pid += ", "
                pid_cnt += 1

        if (pid_cnt >= 1):
            self.m_keepalived_pid = pid[0:-2]
            self.m_keepalived_proc = "running"
        else:
            self.m_keepalived_proc = "not running"

        log.printg("")
        log.printt(98, "# STEP 7. get keepalived binding info" + " " * 32)
        remote_command = "netstat -anp | grep keepalived"
        self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        log.printg("")
        log.printt(98, "# STEP 8. get virtual ip addr" + " " * 40)
        remote_command = "ip addr list %s | grep %s --color=never" \
                         % (self.keepalive_interface, self.virtual_ip)
        result = self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)
        result = result.split('\r\n')
        result = result[1].split(" ")

        if str(result).find(self.virtual_ip) >= 0:
            self.m_virtual_ip = "OK"
        else:
            self.m_virtual_ip = "NOK"

        log.printg("")
        log.printt(98, "# STEP 9. check vrrp protocol packet" + " " * 33)
        remote_command = "timeout 3 tcpdump -i %s -nn vrrp -c 5" % self.vrrp_interface
        results = self.ssh_command_prompt(child, remote_command, self.PROMPT_ROOT, self.LOG_ON, log_flag)

        dump_cnt=0
        results = results.split("\r\n")
        for result in results[1:len(results)-1]:
            if result.find("tcpdump") == -1 and result.find("listening") == -1 \
                    and result.find("VRRP") >= 0:
                dump_cnt += 1

        if dump_cnt >= 1:
            self.m_vrrp_tcp_dump = "OK"
        else:
            self.m_vrrp_tcp_dump = "NOK"

        log.printg("")
        log.printt(98, "# STEP 10. monitoring summary information" + " " * 28)
        log.printb("haproxy version    : %s" % self.m_haproxy_ver)
        log.printb("haproxy process    : %s" % self.m_haproxy_proc)
        log.printb("haproxy pid        : %s" % self.m_haproxy_pid)
        log.printb("haproxy status     : %s" % self.m_haproxy_status)
        log.printb("haproxy ha status  : %s" % self.m_haproxy_ha_status)
        log.printb("keepalived version : %s" % self.m_keepalived_ver)
        log.printb("keepalived procoss : %s" % self.m_keepalived_proc)
        log.printb("keepalived pid     : %s" % self.m_keepalived_pid)
        log.printb("virtual ip addr    : %s(%s)" % (self.m_virtual_ip, self.virtual_ip))
        log.printb("vrrp tcp dump      : %s" % self.m_vrrp_tcp_dump)

        log.printg("")

    ##############################################################################
    # ssh_get_haproxy_service_stat
    ##############################################################################
    def ssh_get_haproxy_service_stat(self, child, log_flag):
        remote_command = "/etc/haproxy/chk_onos_ins"
        result = self.ssh_command_public(child, remote_command, self.PROMPT_PUBLIC, self.LOG_ON, log_flag)
        result = result.split('\r\n')
        for line in result[1:(len(result)-1)]:
            print line

##############################################################################
# main
##############################################################################

log = colorlog.ColorLog(LOG_FLAG)

if __name__ == "__main__":
    print "MAIN"
