#!/usr/bin/python
# -*- coding: iso-8859-1 -*-
#################################################################################
# Extention to the simple FritzCap python port
# Simplifies generation and examination of traces taken from AVM FritzBox and/or SpeedPort
# Traces can be examined using WireShark
# (c) tom2bor 2011 (tom2bor in http://www.ip-phone-forum.de/)
# based on the Windows GUI exe with same name
##################################################################################
# Copyright (c) 2011, tom2bor
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    * Neither the name of the <organization> nor the
#      names of its contributors may be used to endorse or promote products
#      derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##################################################################################

import sys, platform, signal
import datetime
import re
import argparse
import ConfigParser
import threading
import Queue
import time, random
import getpass

import logging
import logging.config
import os

# go to the real path, even if the started script is the symbilic link
scriptname = sys.argv[0]
realpath = os.path.dirname(os.path.realpath(scriptname))
os.chdir(realpath+"/")

# add the real directories containing the python modules to the sys path
sys.path.append(realpath+"/")
sys.path.append(realpath+'/core/')

# import modules
from capfile_worker import CapfileWorker
from capture_monitor import CaptureMonitor
from call_monitor import CallMonitor
from interfaces_dumper import InterfacesDumper
from sysinput_reader import SytemInputFileReader
from string_helper import StringHelper
from log import Log

def signal_handler(signum, stack):
    logger.debug("Become signal from the system (signum:'%s', stack:'%s')." % (signum,stack))
    #logger.debug("before:%s" % (still_working))
    global still_working
    still_working = False

    for thread in all_threads:
        logger.debug("Call stop method to the thread:'%s'" % (thread))
        thread.stop()
        logger.debug("Call join signal to the thread:'%s'" % (thread))
        thread.join()

    logger.debug("Become signal from the system (signum:'%s', stack:'%s') finished." % (signum,stack))


if __name__ == '__main__':
    # tstart: time of program start
    # tcall: time of ring/call (_Y: year)
    # tconn: time of connection
    # tdisc: time of disconnection
    # tcaps: time of starting capture
    # tcape: time of ending capture
    # caller: the caller numer/name (id,nr,name,)
    # dialed: the dialed number/name
    # acalls: active calls number
    # lineport: the used line port name (SIP0,SIP1,etc.)

    global data_map
    data_map = {}
    data_map['tstart'] = datetime.datetime.now()
    data_map['tocall'] = datetime.datetime(1900,1,1)
    data_map['tcall'] = datetime.datetime(1900,1,1)
    data_map['tconn'] = datetime.datetime(1900,1,1)
    data_map['toconn'] = datetime.datetime(1900,1,1)
    data_map['todisc'] = datetime.datetime(1900,1,1)
    data_map['tdisc'] = datetime.datetime(1900,1,1)
    data_map['tcaps'] = datetime.datetime(1900,1,1)
    data_map['tcape'] = datetime.datetime(1900,1,1)

#    data_str = 'captures/%(tcall.Ymd)-%(tcall.m)-%(tcall.d)/%(tcall.H)%(tcall.M)_%(call.name)s/'
#    value_str = StringHelper.parse_string(data_str, data_map)

    global logger
    global all_threads
    global work_queue

    work_queue = None
    all_threads = []

    global still_working
    still_working = True

    parser = argparse.ArgumentParser(description='fritzcap - audio files analyse', add_help=True)
    main_args = parser.add_argument_group('main arguments')
    ext_args = parser.add_argument_group('extended defaults arguments')

    fritzcap_version = '2.3.1'
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + fritzcap_version)

    main_args.add_argument('-c', '--capture_files', default=None, action='store_true', help='capture file/s. If the monitor option is not set, only one file will be captured')
    main_args.add_argument('-d', '--decode_files', nargs='*', metavar='file', type=str, help='the list of captured files to decode. All the new captures files will be decode automatically if the --capture switch is set. Read the files from the standard input if the list of files is empty and there is no capture work.')
    main_args.add_argument('-m', '--monitor_calls', default=None, action='store_true', help='start the call monitor mode. The CALL/RING/DISCONNECT events will be used to start/stop the capture automatically')
    main_args.add_argument('-p', '--password', default=None, metavar='password', type=str, help='the password to login to the box. If not set and --login_not_required is set to False, then the password will be read from the console')
    main_args.add_argument('-u', '--username', default=None, metavar='username', type=str, help='the username to login to the box (Default:\'root\')')
    main_args.add_argument('-s', '--show_interfaces', default=None, action='store_true', help='shows the interfaces as key/description pairs')

    ext_args.add_argument('--config_file', default='fritzcap.conf', metavar='path_to_file', type=file, help='the fritzcap configuration file (Default:\'fritzcap.conf\')')
    ext_args.add_argument('--logging_config', default=None, metavar='path_to_file', type=str, help='the fritzcap logging configuration file (Default:\'logging.conf\')')
    ext_args.add_argument('--box_name', default=None, metavar='host_or_IP', type=str, help='the host name or IP address of the FritzBox (Default:\'fritz.box\')')
    ext_args.add_argument('--call_service_port', default=None, metavar='port', type=int, help='the port number of the FritzBox call monitor telnet service (Default:1012)')
    ext_args.add_argument('--login_not_required', default=None, action='store_true', help='set this flag, if the login is not needed to connect to the box')
    ext_args.add_argument('--protocol', default=None, metavar='protocol', type=str, help='the protocol to used to login to the FritzBox (Default: \'http\')')
    ext_args.add_argument('--cap_folder', default=None, metavar='path_pattern', type=str, help='the folder where the capture files will be stored (Default:\'captures/%%d%%m%%Y%%H%%M/\')')
    ext_args.add_argument('--cap_file', default=None, metavar='file_pattern', type=str, help='the file name where the capture data will be saved (Default:\'capture.cap\')')
    ext_args.add_argument('--cap_interface', default=None, metavar='cap_interface', type=str, help='the key of the interface to capture data from (Default:\'3-17\' means value \'internet\')')
    ext_args.add_argument('--after_capture_time', default=None, metavar='time_in_seconds', type=int, help='time in seconds how long the capture monitor should still continue capture files after all calls were finished (Default:10)')
    ext_args.add_argument('--decode_workers_count', default=None, metavar='int', type=int, help='the count parallel workers to decode captures files. The minimal value is 1 (Default:2).')
    args = parser.parse_args()

    # read the config file
    config = ConfigParser.RawConfigParser()
    config.readfp(args.config_file)

    # set the defaults
    defaults = {"capture_files": False,
                "decode_files": None,
                "monitor_calls": False,
                "password": None,
                "username": "root",
                "show_interfaces": False,
                "logging_config": "logging.conf",
                "box_name": "fritz.box",
                "call_service_port": 1012,
                "login_not_required": None,
                "protocol": "http",
                "cap_folder": "captures/%(tcaps.Y-m-d/HMS)/",
                "cap_file": "capture.cap",
                "cap_interface": " ", # needs to be a space as empty string fails with `TypeError: cannot concatenate 'str' and 'NoneType' objects`
                "after_capture_time": 10,
                "decode_workers_count": 2,
                "after_capture_time": 10,
                "default_login": 'getpage=../html/de/menus/menu2.html&errorpage=../html/index.html&var:lang=de&var:pagename=home&var:menu=home&=&login:command/password=%s',
                "sid_challenge": 'getpage=../html/login_sid.xml',
                "sid_login": 'login:command/response=%s&getpage=../html/login_sid.xml',
                "start_str": '?start=1&start1=Start',
                "stop_str": '?stop=1&stop1=Stop'
                }

    # read the values from commandline parameter -> config parameters -> default value
    for key, default_value in defaults.items():
        value = None
        if (args.__contains__(key)):
            value = args.__getattribute__(key)

        if (value is None) and config.has_option("settings", key) and config.get("settings", key):
            value = config.get("settings", key)

        if (value is None) and default_value:
            value = default_value

        args.__setattr__(key,value)

    login_required  = not args.login_not_required
    nothing_to_do   = True # will be set to False if at least one action will be executed


    ###################################################
    ### read the dictionary data from config file   ###
    ###################################################
    for (pbook_number, pbook_name) in config.items("phone_book"):
        data_map["pbook_number."+pbook_number]=pbook_name
        data_map["pbook_name."+pbook_name]=pbook_number


    ######################################
    ### init logger service            ###
    ######################################
    Log().file_config(args.logging_config)
    logger = Log().getLogger()
    # print out debug data
    logger.info("FritzCap version %s started." % fritzcap_version)
    if (logger.isEnabledFor(logging.DEBUG)):
        logger.debug("Command line parameters: " + str(sys.argv))
        logger.debug("Parsed parameters:       " + str(args))


    # take the password data from the command line
    if (args.capture_files or args.show_interfaces) and (args.password is None) and login_required:
        platform_system = platform.system()
        if (platform_system == "Windows"):
            signal.signal(signal.SIGINT, signal_handler)
            args.password = getpass.win_getpass("Enter the FritzBox password:")
        elif ((platform_system == "Linux") or (platform_system == "Darwin")):
            signal.signal(signal.SIGINT, signal_handler)
            args.password = getpass.unix_getpass("Enter the FritzBox password:")
        else:
            logger.warning("Need a password, but don't know how to ask as unknown platform: %s" % platform.system())

    ######################################
    ### show the interfaces            ###
    ######################################
    interfaces_dumper = None
    if (args.show_interfaces is not None):
        nothing_to_do = False
        interfaces_dumper = InterfacesDumper(args.box_name, args.username, args.password, args.protocol, login_required, args.default_login, args.sid_challenge, args.sid_login)
        all_threads.insert(0, interfaces_dumper)

    ######################################
    ### init decode workers service    ###
    ######################################
    if (args.decode_files is not None):
        nothing_to_do = False
        work_queue = Queue.Queue(0)

        if (args.decode_workers_count < 1):
            logger.warning("The workers count is '< 1' now and will be set to '1'. At least 1 worker have to be active to do decode work.")
            args.decode_workers_count = 1

        for i in range(args.decode_workers_count):
            all_threads.insert(0, CapfileWorker(i, work_queue)) # create a worker

        if (len(args.decode_files) > 0):
            # there is at least one file to decode throw the command line parameter.
            # Decode all the files
            for file in args.decode_files:
                work_queue.put(file)
            if (not args.monitor_calls and not args.capture_files):
                # put the last queue item if the monitor option is not activated
                work_queue.put(None)
        elif (not args.monitor_calls and not args.capture_files):
            # read the files to decode from system.in,
            # because there are no files given throw the command line
            # and monitor mode is not used
            all_threads.insert(0, SytemInputFileReader(work_queue));

    ######################################
    ### init capture monitor service   ###
    ######################################
    capture_monitor = None
    if (args.capture_files):
        nothing_to_do = False
        capture_monitor = CaptureMonitor(work_queue, data_map, args.box_name, args.username, args.password, args.protocol, args.cap_folder, args.cap_file, args.cap_interface, login_required, args.default_login, args.sid_challenge, args.sid_login, args.start_str, args.stop_str, args.after_capture_time)
        all_threads.insert(0, capture_monitor)

    ######################################
    ### init call monitor service      ###
    ######################################
    if (args.monitor_calls):
        nothing_to_do = False
        if (capture_monitor is None):
            logger.info("Note: -m or --monitor_calls without -c or --capture_files does monitoring without capture.")

        call_monitor = CallMonitor(capture_monitor, args.box_name, args.call_service_port)
        all_threads.insert(0, call_monitor)
    elif (args.capture_files):
        # start infinity capture file, because the call_monitor is not started.
        capture_monitor.start_capture();

    if (nothing_to_do):
        logger.warning("Nothing to do. Exiting.")
    else:
        # start all the created threads
        for thread in all_threads:
            thread.start()
            time.sleep(0.1) #wait 100 milliseconds

        signal.signal(signal.SIGINT, signal_handler)
        while (still_working):
            try:
                # logger.debug("Sleep because still_working.")
                time.sleep(1)
                all_finished = True
                for thread in all_threads:
                    if not thread.stopped():
                        all_finished = False
                        break;
                if all_finished:
                    logger.debug("There is no more active threads. Exiting.")
                    still_working = False
            except IOError:
                a = 1 # just do nothing
    logger.info("FritzCap version %s finished." % fritzcap_version)
