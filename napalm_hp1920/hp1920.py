# -*- coding: utf-8 -*-
# Copyright 2016 Dravetech AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""
Napalm driver for HPE OfficeConnect 1920.

Read https://napalm.readthedocs.io for more information.
"""

import re

from netmiko import ConnectHandler

from napalm.base import NetworkDriver
from napalm.base.exceptions import (
    ConnectionException,
    SessionLockedException,
    MergeConfigException,
    ReplaceConfigException,
    CommandErrorException,
)

from napalm.base.utils import py23_compat

# Easier to store these as constants
MINUTE_SECONDS = 60
HOUR_SECONDS = 60 * MINUTE_SECONDS
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS


class HP1920Driver(NetworkDriver):
    """Napalm driver for HPE OfficeConnect 1920."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor."""
        if optional_args is None:
            optional_args = {}
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        # Netmiko possible arguments
        netmiko_argument_map = {
            'port': None,
            'secret': '',
            'verbose': False,
            'keepalive': 30,
            'global_delay_factor': 1,
            'use_keys': False,
            'key_file': None,
            'ssh_strict': False,
            'system_host_keys': False,
            'alt_host_keys': False,
            'alt_key_file': '',
            'ssh_config_file': None,
            'allow_agent': False,
        }

        # Build dict of any optional Netmiko args
        self.netmiko_optional_args = {}
        for k, v in netmiko_argument_map.items():
            try:
                self.netmiko_optional_args[k] = optional_args[k]
            except KeyError:
                pass

    def open(self):
        """Open a connection to the device."""
        self.device = ConnectHandler(
            device_type='hp_comware',
            host=self.hostname,
            username=self.username,
            password=self.password,
            **self.netmiko_optional_args)
        self.device.send_command_timing("_cmdline-mode on \n Y\nJinhua1920unauthorized")

    def close(self):
        """Close the connection to the device."""
        self.device.disconnect()

    def disable_paging(self):
        """ Disable paging on the device """
        out_disable_paging = self.device.send_command('screen-length disable')
        if 'configuration is disabled for current user' in out_disable_paging:
            pass
        else:
            raise CommandErrorException("Disable Paging cli command error: {}".format(out_disable_paging))

    def get_facts(self):
        """
        Returns a dictionary containing the following information:
         * uptime - Uptime of the device in seconds.
         * vendor - Manufacturer of the device.
         * model - Device model.
         * hostname - Hostname of the device
         * fqdn - Fqdn of the device
         * os_version - String with the OS version running on the device.
         * serial_number - Serial number of the device
         * interface_list - List of the interfaces of the device

        Example::

            {
            'uptime': 151005.57332897186,
            'vendor': u'Arista',
            'os_version': u'4.14.3-2329074.gaatlantarel',
            'serial_number': u'SN0123A34AS',
            'model': u'vEOS',
            'hostname': u'eos-router',
            'fqdn': u'eos-router',
            'interface_list': [u'Ethernet2', u'Management1', u'Ethernet1', u'Ethernet3']
            }

        """
        self.disable_paging()
        out_display_version = self.device.send_command("display version").split("\n")
        uptime = None
        ver_str = None
        for line in out_display_version:
            if "Software, Version " in line:
                ver_str = line.split("Version ")[-1]
            elif " uptime is " in line:
                uptime_str = line.split("uptime is ")[-1]
                # print("Uptime String : {}".format(uptime_str))
                # Exapmples of uptime_str
                # '57 weeks, 1 day, 7 hours, 53 minutes'
                # '2 years, 57 weeks, 1 day, 7 hours, 53 minutes'
                # '53 minutes'
                match = re.findall(r'(\d+)\s*(\w+){0,5}', uptime_str)
                for timer in match:
                    if 'year' in timer[1]:
                        uptime += int(timer[0]) * YEAR_SECONDS
                    elif 'week' in timer[1]:
                        uptime += int(timer[0]) * WEEK_SECONDS
                    elif 'day' in timer[1]:
                        uptime += int(timer[0]) * DAY_SECONDS
                    elif 'hour' in timer[1]:
                        uptime += int(timer[0]) * HOUR_SECONDS
                    elif 'minute' in timer[1]:
                        uptime += int(timer[0]) * MINUTE_SECONDS

        out_display_device = self.device.send_command("display device manuinfo")
        match = re.findall(r"""^Slot\s+(\d+):\nDEVICE_NAME\s+:\s+(.*)\nDEVICE_SERIAL_NUMBER\s+:\s+(.*)\nMAC_ADDRESS\s+:\s+([0-9a-fA-F]{1,4}-[0-9a-fA-F]{1,4}-[0-9a-fA-F]{1,4})\nMANUFACTURING_DATE\s+:\s+(.*)\nVENDOR_NAME\s+:\s+(.*)""", out_display_device, re.M)
        snumber = set()
        vendor = set()
        hwmodel = set()
        for idx in match:
            slot, dev, sn, mac, date, ven = idx
            snumber.add(sn)
            vendor.add(ven)
            hwmodel.add(dev)

        out_display_current_config = self.device.send_command("display current-configuration")
        hostname = ''.join(re.findall(r'.*\s+sysname\s+(.*)\n', out_display_current_config, re.M))
        interfaces = re.findall(r'\ninterface\s+(.*)\n', out_display_current_config, re.M)
        facts = {
            "uptime": uptime,
            "vendor": py23_compat.text_type(','.join(vendor)),
            "os_version": py23_compat.text_type(ver_str),
            "serial_number": py23_compat.text_type(','.join(snumber)),
            "model": py23_compat.text_type(','.join(hwmodel)),
            "hostname": py23_compat.text_type(hostname),
            "fqdn": py23_compat.text_type(hostname),
            "interface_list": interfaces
        }
        return facts

    def get_mac_address_table(self):

        """
        Returns a lists of dictionaries. Each dictionary represents an entry in the MAC Address
        Table, having the following keys:
            * mac (string)
            * interface (string)
            * vlan (int)
            * active (boolean)
            * static (boolean)
            * moves (int)
            * last_move (float)

        However, please note that not all vendors provide all these details.
        E.g.: field last_move is not available on JUNOS devices etc.

        Example::

            [
                {
                    'mac'       : '00:1C:58:29:4A:71',
                    'interface' : 'Ethernet47',
                    'vlan'      : 100,
                    'static'    : False,
                    'active'    : True,
                    'moves'     : 1,
                    'last_move' : 1454417742.58
                },
                {
                    'mac'       : '00:1C:58:29:4A:C1',
                    'interface' : 'xe-1/0/1',
                    'vlan'       : 100,
                    'static'    : False,
                    'active'    : True,
                    'moves'     : 2,
                    'last_move' : 1453191948.11
                },
                {
                    'mac'       : '00:1C:58:29:4A:C2',
                    'interface' : 'ae7.900',
                    'vlan'      : 900,
                    'static'    : False,
                    'active'    : True,
                    'moves'     : None,
                    'last_move' : None
                }
            ]
        """
        # Disable paging of the device
        self.disable_paging()

        # <device>display mac-address
        # MAC ADDR       VLAN ID  STATE          PORT INDEX               AGING TIME(s)
        # 2c41-3888-24a7 1        Learned        Bridge-Aggregation30     AGING
        # a036-9f00-1dfa 1        Learned        Bridge-Aggregation30     AGING
        # a036-9f00-29c5 1        Learned        Bridge-Aggregation31     AGING
        # a036-9f00-29c6 1        Learned        Bridge-Aggregation31     AGING
        # b8af-675c-0800 1        Learned        Bridge-Aggregation2      AGING
        out_mac_table = self.device.send_command('display mac-address')
        mactable = re.findall(r'^([0-9a-fA-F]{1,4}-[0-9a-fA-F]{1,4}-[0-9a-fA-F]{1,4})\s+(\d+)\s+(\w+)\s+([A-Za-z0-9-/]{1,40})\s+(.*)', out_mac_table, re.M)
        output_mactable = []
        record = {}
        for rec in mactable:
            mac, vlan, state, port, aging = rec
            record['mac'] = self._format_mac_cisco_way(mac)
            record['interface'] = self._normalize_port_name(port)
            record['vlan'] = vlan
            record['static'] = 'None'
            record['active'] = 'None'
            record['moves'] = 'None'
            record['last_move'] = 'None'
            output_mactable.append(record)
        return output_mactable

    def get_arp_table(self):

        """
        Returns a list of dictionaries having the following set of keys:
            * interface (string)
            * mac (string)
            * ip (string)
            * age (float)

        Example::

            [
                {
                    'interface' : 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '5C:5E:AB:DA:3C:F0',
                    'ip'        : '172.17.17.1',
                    'age'       : 1454496274.84
                },
                {
                    'interface' : 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '5C:5E:AB:DA:3C:FF',
                    'ip'        : '172.17.17.2',
                    'age'       : 1435641582.49
                }
            ]

        """
        # Disable Pageing of the device
        self.disable_paging()
        out_arp_table = self.device.send_command('display arp')
        arptable = re.findall(
            r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{1,4}-[0-9a-fA-F]{1,4}-[0-9a-fA-F]{1,4})\s+(\d+)\s+([A-Za-z0-9-/]{1,40})\s+(\d+)\s+(\w+)\n',
            out_arp_table, re.M)
        output_arptable = []
        record = {}
        for rec in arptable:
            ip, mac, vlan, port, aging, arp_type = rec
            record['interface'] = self._normalize_port_name(port)
            record['mac'] = self._format_mac_cisco_way(mac)
            record['ip'] = ip
            record['vlan'] = vlan
            record['aging'] = aging
            output_arptable.append(record)
        return output_arptable

    def get_interfaces_ip(self):

        """
        Returns all configured IP addresses on all interfaces as a dictionary of dictionaries.
        Keys of the main dictionary represent the name of the interface.
        Values of the main dictionary represent are dictionaries that may consist of two keys
        'ipv4' and 'ipv6' (one, both or none) which are themselvs dictionaries witht the IP
        addresses as keys.
        Each IP Address dictionary has the following keys:
            * prefix_length (int)

        Example::

            {
                u'FastEthernet8': {
                    u'ipv4': {
                        u'10.66.43.169': {
                            'prefix_length': 22
                        }
                    }
                },
                u'Loopback555': {
                    u'ipv4': {
                        u'192.168.1.1': {
                            'prefix_length': 24
                        }
                    },
                    u'ipv6': {
                        u'1::1': {
                            'prefix_length': 64
                        },
                        u'2001:DB8:1::1': {
                            'prefix_length': 64
                        },
                        u'2::': {
                            'prefix_length': 64
                        },
                        u'FE80::3': {
                            'prefix_length': u'N/A'
                        }
                    }
                },
                u'Tunnel0': {
                    u'ipv4': {
                        u'10.63.100.9': {
                            'prefix_length': 24
                        }
                    }
                }
            }
        """
        # Disable Pageing of the device
        self.disable_paging()

        out_curr_config = self.device.send_command('display current-configuration')
        ipv4table = re.findall(
            r'^interface\s+([A-Za-z0-9-/]{1,40})\n.*\s+ip\s+address\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\n',
            out_curr_config, re.M)
        # TODO: get device with v6 and update above struct
        # ipv6table = re.findall(r'',out_curr_config,re.M)
        output_ipv4table = []
        iface = {'ipv4': {}, 'ipv6': {}}
        for rec in ipv4table:
            interface, ip, mask = rec
            norm_int = self._normalize_port_name(interface)
            iinterfaces = {norm_int: {'ipv4': {ip: {'prefix_len': mask}}}}
            output_ipv4table.append(iinterfaces)

        return output_ipv4table

    def get_lldp_neighbors(self):
        """
        Returns a dictionary where the keys are local ports and the value is a list of \
        dictionaries with the following information:
            * hostname
            * port

        Example::

            {
            u'Ethernet2':
                [
                    {
                    'hostname': u'junos-unittest',
                    'port': u'520',
                    }
                ],
            u'Ethernet3':
                [
                    {
                    'hostname': u'junos-unittest',
                    'port': u'522',
                    }
                ],
            u'Ethernet1':
                [
                    {
                    'hostname': u'junos-unittest',
                    'port': u'519',
                    },
                    {
                    'hostname': u'ios-xrv-unittest',
                    'port': u'Gi0/0/0/0',
                    }
                ],
            u'Management1':
                [
                    {
                    'hostname': u'junos-unittest',
                    'port': u'508',
                    }
                ]
            }
        """
        # Disable Pageing of the device
        self.disable_paging()

        out_lldp = self.device.send_command('display lldp neighbor-information')
        lldptable = re.findall(
            r'^LLDP.*port\s+\d+\[(.*)\]:\s+.*\s+Update\s+time\s+:\s+(.*)\s+\s+.*\s+.*\s+.*\s+Port\s+ID\s+:\s+(.*)\s+Port\s+description\s:.*\s+System\s+name\s+:\s(.*)\n',
            out_lldp, re.M)
        output_lldptable = {}
        for rec in lldptable:
            local_port, update_time, remote_port, neighbor = rec
            output_lldptable[local_port] = [{'hostname': neighbor, 'port': remote_port}]
        return output_lldptable

    # Util functions
    @staticmethod
    def _format_mac_cisco_way(mac_address):
        """
        function formating mac address to cisco form
        AA:BB:CC:DD:EE:FF
        """
        mac_address = mac_address.replace('-', '')
        return mac_address[:2] +\
            ':' + mac_address[2:4] +\
            ':' + mac_address[4:6] +\
            ':' + mac_address[6:8] +\
            ':' + mac_address[8:10] +\
            ':' + mac_address[10:12]

    @staticmethod
    def _normalize_port_name(res_port):
        """ Convert Short HP interface names to long (ex: BAGG519 --> Bridge-Aggregation 519)"""
        if re.match('^BAGG\d+', res_port):
            # format port BAGG519 --> Bridge-Aggregation 519
            agg_port_name = res_port.replace('BAGG', 'Bridge-Aggregation ')
            return agg_port_name
        elif re.match('^Bridge-Aggregation\d*', res_port):
            agg_port_name = res_port
            return agg_port_name
        elif re.match('^XGE\d.*', res_port):
            # format port XGE1/2/0/7 --> Ten-GigabitEthernet 1/2/0/7
            port_name = res_port.replace('XGE', 'Ten-GigabitEthernet ')
            # print(" --- Port Name: "+'\x1b[1;32;40m' +"{}" .format(port_name)+'\x1b[0m')
            return port_name
        elif re.match('^GE\d.*', res_port):
            # format port GE1/5/0/19 --> GigabitEthernet 1/5/0/19
            port_name = res_port.replace('GE', 'GigabitEthernet ')
            # print(" --- Port Name: "+'\x1b[1;32;40m' +"{}" .format(port_name)+'\x1b[0m')
            return port_name
        elif re.match('^Vlan\d+', res_port):
            # format port Vlan4003 --> Vlan-interface4003
            port_name = res_port.replace('Vlan', 'Vlan-interface')
            # print(" --- Port Name: "+'\x1b[1;32;40m' +"{}" .format(port_name)+'\x1b[0m')
            return port_name
        else:
            return res_port 
            # print('\x1b[1;31;40m' + " --- Unknown Port Name: {} --- ".format(res_port)+'\x1b[0m')
