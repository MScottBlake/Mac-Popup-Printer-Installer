#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
The main purpose of this script is to provide the core framework for a printer
installation in the form of a dropdown list. It was designed to be used in many
different situations such as Jamf Self Service, Apple Remote Desktop, manually
triggered by a technitian, or as a zero-touch lab deployment.

Special thanks to @haircut for the original concept and @gneagle for his work
on FoundationPlist.py.
'''

import argparse
import csv
import json
import logging
import os
import Queue
import subprocess
import sys
import threading
import requests

# PyLint cannot properly find names inside Cocoa libraries, so issues bogus
# No name 'Foo' in module 'Bar' warnings. Disable them.
# pylint: disable=E0611
from Foundation import NSData
from Foundation import NSPropertyListSerialization
from Foundation import NSPropertyListMutableContainers
# pylint: enable=E0611

# Disable snake case naming convention warnings
# pylint: disable=C0103

__version__ = "0.1.0"

CONFIG = {
    "Dialog": {
        "Application": "Pashua", # Options: Pashua or cocoaDialog
        "Title": "Printer Installer",
        "LookupMethod": {
            "Kerberos": False, # Tried first, if enabled
            "NoMAD": True, # Tried second, if enabled
            "Jamf": False # Tried third, if enabled
        }
    },
    "DriverInstallation": {
        "Type": "Jamf" # Options: File, Web, Jamf
    },
    "Log": {
        "Debug": False,
        "Path": "/Library/Logs/printer_installer.log"
    },
    "QueueDefinitions": {
        "Location": "File", # Options: File, Web, SharePoint
        "Type": "csv", # Options: csv, json
        "Path": "/path/to/queue/definitions.csv"
    },
    "JamfAPI": { # Only necessary if 'Jamf' selected above
        "URL": "https://your.jamfserver.com:8443/JSSResource",
        "Username": "api-user",
        "Password": "super-long-api-password"
    }
}
DATA_CACHE = {}
THREAD_DATA = []
THREAD_QUEUE = Queue.Queue()

###############################################################################
# Program Logic - Here be dragons!
###############################################################################

def check_driver_exists(driver_path):
    '''
    Returns a boolean value indicating whether a given driver exists on the system.
    '''
    if os.path.exists(driver_path):
        LOGGER.debug("The driver exists at %s", driver_path)
        return True

    LOGGER.warning("The driver was not found at %s", driver_path)
    return False


def check_matches_filter(args, queue):
    '''Returns a boolean value indicating whether a given queue matches the given filter.'''
    if args.filter_key and queue.get(args.filter_key):
        LOGGER.debug('Filter Key is set (%s). Checking %s...',
                     args.filter_key, queue.get('PrinterName'))
        if args.filter_value not in queue.get(args.filter_key):
            LOGGER.debug('Hiding %s: Filter Value does not match (Looking for %s, got %s)',
                         queue.get('PrinterName'), args.filter_value, queue.get(args.filter_key))
            return False

        LOGGER.debug('%s passed the Filter Key check.', queue.get('PrinterName'))

    return True


def check_matches_ad_groups(queue, user_groups):
    '''
    Returns a boolean value indicating whether a given queue matches the given
    AD Security Group.
    '''
    if not queue.get('ADFilterGroup'):
        return True

    if user_groups and queue.get('ADFilterGroup') in user_groups:
        LOGGER.debug('Showing %s: ADFilterGroup found in User Groups',
                     queue.get('PrinterName'))
        return True

    LOGGER.debug('Hiding %s: ADFilterGroup not found in User Groups',
                 queue.get('PrinterName'))
    return False


def check_printer_installed(queue):
    '''Returns a boolean value indicating whether a given queue is already installed.'''
    existing_queues = get_currently_mapped_queues()

    if queue.get('PrinterName') in existing_queues:
        LOGGER.debug('Hiding %s: PrinterName is already installed', queue.get('PrinterName'))
        return True

    if queue.get('DisplayName') in existing_queues:
        LOGGER.debug('Hiding %s: DisplayName is already installed', queue.get('DisplayName'))
        return True

    return False


def display_message_dialog(message):
    '''Generate a dialog that shows a message.'''
    LOGGER.debug("Displaying dialog to show this message: %s", message)
    dialog_app = CONFIG.get('Dialog').get('Application').lower()

    if dialog_app == "pashua":
        return display_message_dialog_pashua(message)
    elif dialog_app == "cocoadialog":
        return display_message_dialog_cocoaDialog(message)
    else:
        LOGGER.critical("Unknown dialog type '%s'. Cannot display dialogs.", dialog_app)
        raise ValueError("Unknown dialog type '"+dialog_app+"'. Cannot display dialogs.")


def display_message_dialog_pashua(message):
    '''Generate a dialog that shows a message using Pashua.'''
    conf = pashua_config_dialog_window()
    conf += u"""
    txt.type = text
    txt.default = """ + message + """
    db.type = defaultbutton
    db.label = Okay
    """

    pashua_launch(conf.encode('utf8'))


def display_message_dialog_cocoaDialog(message):
    '''Generate a dialog that shows a message using cocoaDialog.'''
    dialog_title = CONFIG.get('Dialog').get('Title')
    dialog = subprocess.Popen(
        [locate_dialog_bundle_path("cocoaDialog"),
         'ok-msgbox',
         '--title', dialog_title,
         '--text', dialog_title,
         '--informative-text', message,
         '--float', '--no-cancel']
    )
    _ = dialog.communicate()


def display_queue_selection_dialog(args):
    '''Generate the printer selector dialog.'''
    dialog_app = CONFIG.get('Dialog').get('Application').lower()

    if dialog_app == "pashua":
        return display_queue_selection_dialog_pashua(args)
    elif dialog_app == "cocoadialog":
        return display_queue_selection_dialog_cocoaDialog(args)
    else:
        LOGGER.critical("Unknown dialog type '%s'. Cannot display dialogs.", dialog_app)
        raise ValueError("Unknown dialog type '"+dialog_app+"'. Cannot display dialogs.")


def display_queue_selection_dialog_cocoaDialog(args):
    '''Generate the printer selector dialog using cocoaDialog.'''
    printer_list = generate_available_queue_list(args)

    if not printer_list:
        display_message_dialog("All available print queues are already installed.")

    # Get path to the executable inside cocoaDialog.app
    app_path = locate_dialog_bundle_path("cocoaDialog")

    LOGGER.info('Prompting user to select desired queue')
    queue_dialog = subprocess.Popen([app_path, 'dropdown', '--string-output',
                                     '--float', '--icon', 'gear',
                                     '--title', CONFIG.get('Dialog').get('Title'),
                                     '--text', ('Choose a print queue to '
                                                'add to your computer:'),
                                     '--button1', 'Add',
                                     '--button2', 'Cancel',
                                     '--items'] + printer_list,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
    prompt_return, _ = queue_dialog.communicate()
    if prompt_return == "Cancel\n":
        LOGGER.info('User canceled queue selection')
        return False

    selected_queue = prompt_return.splitlines()[1]
    LOGGER.info('User selected queue %s', selected_queue)
    return selected_queue


def display_queue_selection_dialog_pashua(args):
    '''Generate the printer selector dialog using Pashua.'''
    # Configure the dialog
    conf = pashua_config_dialog_window()
    conf += pashua_config_dialog_cancel_button()
    conf += pashua_config_dialog_add_button()
    conf += pashua_config_dialog_printer_list(args)

    result = pashua_launch(conf.encode('utf8'))

    if CONFIG.get('Log').get('Debug', False):
        LOGGER.debug("Pashua returned the following dictionary keys and values:")
        for key, val in result.iteritems():
            LOGGER.debug("%s = %s", key, val)

    LOGGER.info("Returning '%s' from dialog", result.get('avail_queue', ''))
    return result.get('avail_queue', '')


def generate_available_queue_list(args):
    '''Return a list of queue names that are eligible to be installed.'''
    if not DATA_CACHE.get('available_queues'):
        available_queues = []

        lookup_method = CONFIG.get('Dialog').get('LookupMethod')
        LOGGER.debug("Defined lookup method(s): %s", lookup_method)

        if lookup_method.get('NoMAD') and has_nomad(args):
            user_groups = nomad_get_user_groups(args)
            available_queues = generate_queue_list(args, user_groups)

        elif lookup_method.get('Kerberos') and has_kerberos_ticket():
            user_groups = ldap_get_user_groups(args)
            available_queues = generate_queue_list(args, user_groups)

        elif lookup_method.get('Jamf'):
            available_queues = jamf_generate_queue_list(args)

        LOGGER.debug('Caching available_queues: %s', available_queues)
        DATA_CACHE['available_queues'] = available_queues

    return DATA_CACHE.get('available_queues')


def generate_queue_list(args, user_groups):
    '''Generate the list of available queues.'''
    dialog_list = []

    LOGGER.info('Building the list of available queues')
    for queue in get_queue_definitions().values():
        # Skip if the PrinterName field is present and is already installed
        if check_printer_installed(queue):
            continue

        # Skip if a filter is enabled and it doesn't match
        if not check_matches_filter(args, queue):
            continue

        # Skip if a filter group is configured for this printer and the
        # user is not a member of the group
        if not check_matches_ad_groups(queue, user_groups):
            continue

        # Add the queue to the list of available queues
        dialog_list.append(queue.get('PrinterName'))

    return sorted(dialog_list)


def get_currently_mapped_queues():
    '''Return a list of print queues currently mapped on the system.'''
    if not DATA_CACHE.get('current_queues'):
        try:
            LOGGER.info('Gathering list of currently mappped queues')
            lpstat_result = subprocess.check_output(['/usr/bin/lpstat', '-p'])
        except subprocess.CalledProcessError:
            LOGGER.warning('No current print queues found')
            lpstat_result = None

        current_queues = []
        if lpstat_result:
            for line in lpstat_result.splitlines():
                current_queues.append(line.split()[1])

        LOGGER.debug('Caching current_queues: %s', current_queues)
        DATA_CACHE['current_queues'] = current_queues

    return DATA_CACHE.get('current_queues')


def get_queue_definitions(item=None):
    '''
    Retrieves a list of queue definitions in either csv or json format and
    returns it as a json object.
    '''
    if not DATA_CACHE.get('queue_definitions'):
        queue_type = CONFIG.get('QueueDefinitions').get('Type').lower()

        if queue_type == "csv":
            definitions = get_queue_definitions_csv()
        elif queue_type == "json":
            definitions = get_queue_definitions_json()
        else:
            LOGGER.error("Invalid queue definition type. Expected 'csv'"
                         " or 'json'. Received '%s'", queue_type)
            raise ValueError("Invalid queue definition type. Expected 'csv'"
                             " or 'json'. Received '"+queue_type+"'")

        LOGGER.debug('Caching queue_definitions: %s', definitions)
        DATA_CACHE['queue_definitions'] = definitions

    if item:
        return DATA_CACHE.get('queue_definitions').get(item)

    return DATA_CACHE.get('queue_definitions')


def get_queue_definitions_csv():
    '''
    Retrieves a list of queue definitions in csv format and returns it as a
    json object.
    '''
    queue_location = CONFIG.get('QueueDefinitions').get('Location').lower()

    if queue_location == "file":
        f = open(CONFIG.get('QueueDefinitions').get('Path'), 'r')

        lines = {}
        for line in csv.DictReader(f):
            if line['Options']:
                opts = dict(item.split('=') for item in line['Options'].split(' '))
                line['Options'] = opts
            lines[line['PrinterName']] = line

        data = json.dumps(lines, sort_keys=True, indent=4, separators=(',', ': '))
        f.close()
    elif queue_location == "web":
        # TODO: Get csv queue definitions via web
        pass
    elif queue_location == "sharepoint":
        # TODO: Get csv queue definitions via sharepoint
        pass
    else:
        LOGGER.error("Invalid queue definition location. Expected 'file', "
                     "'web', or 'sharepoint'. Received '%s'", queue_location)
        raise ValueError("Invalid queue definition location. Expected 'file', "
                         "'web', or 'sharepoint'. Received '"+queue_location+"'")

    return json.loads(data)


def get_queue_definitions_json():
    '''
    Retrieves a list of queue definitions in json format and returns it as a
    json object.
    '''
    queue_location = CONFIG.get('QueueDefinitions').get('Location').lower()

    if queue_location == "file":
        f = open(CONFIG.get('QueueDefinitions').get('Path'), 'r')
        data = json.loads(f.read())
        data = json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))
        f.close()
    elif queue_location == "web":
        # TODO: Get json queue definitions via web
        pass
    elif queue_location == "sharepoint":
        # TODO: Get json queue definitions via sharepoint
        pass
    else:
        LOGGER.error("Invalid queue definition location. Expected 'file', "
                     "'web', or 'sharepoint'. Received '%s'", queue_location)
        raise ValueError("Invalid queue definition location. Expected 'file', "
                         "'web', or 'sharepoint'. Received '"+queue_location+"'")

    return json.loads(data)


def has_kerberos_ticket():
    '''Returns a boolean value indicating whether a Kerberos ticket exists.'''
    return not subprocess.check_call(['klist', '-s'], stderr=open(os.devnull, 'wb'))


def has_nomad(args):
    '''Returns a boolean value indicating whether NoMAD is installed.'''
    plist_path = u'/Users/'+args.username+'/Library/Preferences/com.trusourcelabs.NoMAD.plist'
    return os.path.exists(plist_path)


def install_driver(driver_installer):
    '''Installs the required print drivers.'''
    LOGGER.info("Attempting to install drivers via '%s'", driver_installer)
    install_type = CONFIG.get('DriverInstallation').get('Type').lower()

    if install_type == "file":
        # TODO: Install driver via file
        return False
    elif install_type == "web":
        # TODO: Install driver via web
        return False
    elif install_type == "jamf":
        return jamf_run_policy(driver_installer)
    else:
        LOGGER.error("Invalid driver installation type. Expected 'file', "
                     "'web', or 'jamf'. Received '%s'", driver_installer)
        raise ValueError("Invalid driver installation type. Expected 'file', "
                         "'web', or 'jamf'. Received '"+driver_installer+"'")


def install_printer(queue_name):
    """Add the printer queue to the computer"""
    queue = get_queue_definitions(queue_name)

    # If the queue definition doesn't specify a driver, use the generic
    # postscript driver.
    if not queue.get('Driver'):
        LOGGER.info("%s uses a generic driver", queue.get('PrinterName'))
        queue['Driver'] = ("/System/Library/Frameworks/ApplicationServices.framework/Versions/A"
                           "/Frameworks/PrintCore.framework/Versions/A/Resources/Generic.ppd")

    if not check_driver_exists(queue.get('Driver')):
        install_driver(queue.get('DriverInstaller'))

    # if not check_driver_exists(queue.get('Driver')):
    #     LOGGER.error("")

    # Common command
    cmd = ['/usr/sbin/lpadmin',
           '-p', queue.get('DisplayName'),
           '-L', queue.get('Location'),
           '-E',
           '-v', queue.get('URI'),
           '-P', queue.get('Driver')]

    # Determine Options
    if queue.get('Options'):
        options = []
        for key, val in queue.get('Options').iteritems():
            options.append('-o')
            options.append(key + '=' + val)
        cmd += options

    mapq = subprocess.Popen(cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=False)
    try:
        _ = mapq.communicate()
        LOGGER.debug("Excuting command: %s", ' '.join(cmd))
        LOGGER.info("Queue '%s' successfully mapped", queue.get('DisplayName'))
        display_message_dialog(
            ("The printer queue '%s' was successfully added. You should now be "
             "able to send jobs to this printer." % queue.get('DisplayName'))
        )
    except subprocess.CalledProcessError:
        LOGGER.debug('Attempted command: %s', ' '.join(cmd))
        LOGGER.warning('There was a problem mapping the queue!')
        display_message_dialog(
            ("There was a problem mapping the printer queue - please try "
             "again. If the problem persists, contact the ITS Service Desk for "
             "further assistance.")
        )


def jamf_generate_queue_list(args):
    '''
    Use the Jamf Pro API to check each group individually (since you can't get
    all of a user's groups at once) and generate the list of available queues.
    '''
    ldap_servers = jamf_get_ldap_server_ids(args.username)

    # Run as the parent thread to cache the data. This prevents each thread
    # from running shell calls.
    get_currently_mapped_queues()

    LOGGER.info('Building the list of available queues')
    for queue in get_queue_definitions().values():
        THREAD_QUEUE.put(queue)

    threads = {}
    for i in range(THREAD_QUEUE.qsize()):
        threads[i] = threading.Thread(target=jamf_worker, args=[args, ldap_servers])
        threads[i].daemon = True
        threads[i].start()

    # Block until all tasks are done
    THREAD_QUEUE.join()

    # if not THREAD_DATA:
    #     LOGGER.warning("No currently-unmapped queues are available")
    #     display_message_dialog("All available printer queues are already installed on your Mac.")
    #     quit()

    return sorted(THREAD_DATA)


def jamf_get_ldap_server_ids(username):
    """Returns a list of LDAP Server IDs from Jamf Pro"""
    if not DATA_CACHE.get('jamf_ldap_servers'):
        LOGGER.info('Gathering list of usable LDAP servers')

        requests_headers = {'Accept': 'application/json'}
        requests_auth = requests.auth.HTTPBasicAuth(
            CONFIG.get('JamfAPI').get('Username'),
            CONFIG.get('JamfAPI').get('Password')
        )

        ldap_servers_request = requests.get(
            '%s/ldapservers' % (CONFIG.get('JamfAPI').get('URL')),
            auth=requests_auth,
            headers=requests_headers
        )
        ldap_servers = []

        for ldap_server in ldap_servers_request.json().get('ldap_servers'):
            if ldap_server.get('id'):
                url = '%s/ldapservers/id/%s/user/%s' % (
                    CONFIG.get('JamfAPI').get('URL'),
                    ldap_server.get('id'),
                    username
                )

                ldap_user_request = requests.get(
                    url, auth=requests_auth, headers=requests_headers).json()
                for ldap_user in ldap_user_request.get('ldap_users'):
                    if ldap_user.get('username') == username:
                        ldap_servers.append(ldap_server.get('id'))

        ldap_servers = sorted(ldap_servers)

        LOGGER.debug('Caching jamf_ldap_servers: %s', ldap_servers)
        DATA_CACHE['jamf_ldap_servers'] = ldap_servers

    return DATA_CACHE.get('jamf_ldap_servers')


def jamf_run_policy(event):
    '''Runs a jamf policy given the provided event trigger.'''
    jamf_policy = subprocess.Popen(['/usr/local/bin/jamf', 'policy', '-event', event],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
    policy_return, _ = jamf_policy.communicate()

    if "No policies were found for the" in policy_return:
        LOGGER.error("Unable to run Jamf policy via trigger %s", event)
        return False
    elif "Submitting log to" in policy_return:
        LOGGER.info("Successfully ran Jamf policy via trigger %s", event)
        return True

    return False


def jamf_worker(args, ldap_servers):
    """This method processes the queue. It should be called within a thread."""
    while True:
        try:
            queue = THREAD_QUEUE.get()

            # Skip if the printer is already installed
            if check_printer_installed(queue):
                THREAD_QUEUE.task_done()
                continue

            # Skip if a filter is enabled and it doesn't match
            if not check_matches_filter(args, queue):
                THREAD_QUEUE.task_done()
                continue

            # Skip if a filter group is configured for this printer and the user is
            # not a member of the group
            if not queue.get('ADFilterGroup'):
                THREAD_QUEUE.task_done()
                continue

            requests_headers = {'Accept': 'application/json'}
            requests_auth = requests.auth.HTTPBasicAuth(
                CONFIG.get('JamfAPI').get('Username'),
                CONFIG.get('JamfAPI').get('Password')
            )

            for ldap_server in ldap_servers:
                url = '%s/ldapservers/id/%d/group/%s/user/%s' % (
                    CONFIG.get('JamfAPI').get('URL'),
                    ldap_server,
                    queue.get('ADFilterGroup'),
                    args.username
                )

                ldap_usergroup_request = requests.get(
                    url, auth=requests_auth, headers=requests_headers).json()
                for usergroup in ldap_usergroup_request.get('ldap_users'):
                    if usergroup.get('is_member') == "Yes":
                        THREAD_DATA.append(queue.get('PrinterName'))

            THREAD_QUEUE.task_done()
        except: # pylint: disable=W0702
            LOGGER.exception("Error within %s", threading.currentThread().getName())
            THREAD_QUEUE.task_done()


def ldap_get_user_groups(args):
    '''Use LDAP to get all of the given user's AD groups.'''
    user_groups = []

    try:
        ldap_dn = subprocess.check_output(['ldapsearch', '-LLL', '-vvvv',
                                           '-b', 'dc=wvu-ad,dc=wvu,dc=edu',
                                           '-H', 'ldap://wvu-ad.wvu.edu',
                                           '-o', 'ldif-wrap=no',
                                           '(&(objectCategory=Person)(objectClass=User)(sAMAccountName='+args.username+'))', # pylint: disable=line-too-long
                                           'dn'])
    except subprocess.CalledProcessError as exception:
        if exception.returncode == 254:
            LOGGER.exception('Encountered an authentication error while searching ldap.')
        else:
            LOGGER.exception('Unknown error searching ldap. (Error code: %d)', exception.returncode)
        return user_groups

    user_dn = ''
    for attribute in ldap_dn.splitlines():
        if attribute.startswith('dn: '):
            user_dn = attribute.split(':')[1].strip()
            break

    search_filter = '(member:1.2.840.113556.1.4.1941:='+user_dn+')'
    if "ITS-PrinterGroup-*" != "":
        search_filter = '(&'+search_filter+'(cn=ITS-PrinterGroup-*))'

    groups = subprocess.check_output(['ldapsearch', '-LLL',
                                      '-b', 'dc=wvu-ad,dc=wvu,dc=edu',
                                      '-H', 'ldap://wvu-ad.wvu.edu',
                                      '-o', 'ldif-wrap=no',
                                      search_filter,
                                      'cn'])
    for attribute in groups.splitlines():
        if attribute.startswith('cn: '):
            user_groups.append(attribute.split(':')[1].strip())

    return sorted(user_groups)


def locate_dialog_bundle_path(app, path=None):
    '''Locate the full path to the desired dialog application.'''
    app_lower = app.lower()

    if app_lower == "pashua":
        bundle_path = "Pashua.app/Contents/MacOS/Pashua"
    elif app_lower == "cocoadialog":
        bundle_path = "cocoaDialog.app/Contents/MacOS/cocoaDialog"
    else:
        LOGGER.critical("Unknown dialog type '%s'. Cannot display dialogs.", app)
        raise ValueError("Unknown dialog type '"+app+"'. Cannot display dialogs.")

    locations = [
        os.path.join(os.path.dirname(sys.argv[0]), app),
        os.path.join(os.path.dirname(sys.argv[0]), bundle_path),
        os.path.join(".", bundle_path),
        os.path.join(os.path.expanduser("~/Applications"), bundle_path),
        os.path.join("/Applications", bundle_path),
        os.path.join("/Applications/Utilities", bundle_path),
        os.path.join("/usr/local/bin", bundle_path)
    ]

    if path:
        # Custom path given
        locations.insert(0, path + '/' + bundle_path)

    for location in locations:
        if os.path.exists(location):
            return location

    LOGGER.critical("Unable to locate the %s application.", app)
    raise IOError("Unable to locate the "+app+" application.")


def nomad_get_user_groups(args):
    '''Use NoMAD to get all of the given user's AD groups.'''
    plist_path = u'/Users/'+args.username+'/Library/Preferences/com.trusourcelabs.NoMAD.plist'
    if not os.path.exists(plist_path):
        LOGGER.warning('NoMAD plist not found at %s', plist_path)
        return []

    plist = read_plist(plist_path)

    LOGGER.debug('Groups returned from NoMAD plist: %s', plist.get('Groups'))
    return plist.get('Groups')


def pashua_config_dialog_add_button():
    '''Return the configuration options to create an add button within the dialog window.'''
    return u"""
    db.type = defaultbutton
    db.label = Add
    db.tooltip = Add the delected print queue to your computer
    """


def pashua_config_dialog_cancel_button():
    '''Return the configuration options to create a cancel button within the dialog window.'''
    return u"""
    cb.type = cancelbutton
    cb.tooltip = Cancel and do not add any printers
    """


def pashua_config_dialog_printer_list(args):
    '''Return the configuration options to create a cancel button within the dialog window.'''
    conf = u"""
    avail_queue.type = popup
    avail_queue.label = Choose a print queue to add to your computer
    avail_queue.tooltip = Choose a print queue to add to your computer
    avail_queue.mandatory = true
    """

    for printer_name in generate_available_queue_list(args):
        conf += u"avail_queue.option = " + printer_name + "\n"

    return conf


def pashua_config_dialog_window():
    '''Return the configuration options to set the dialog window title.'''
    return u"*.title = " + CONFIG.get('Dialog').get('Title')


# Calls the pashua executable, parses its result string and generates
# a dictionary that's returned.
def pashua_launch(config_data, pashua_path=None):
    '''Display a dialog box based on given configuration data'''
    # Get path to the executable inside Pashua.app
    app_path = locate_dialog_bundle_path("Pashua", pashua_path)

    # Send string to pashua standard input, receive result.
    shell = subprocess.Popen([app_path, "-"],
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    shell_result, _ = shell.communicate(input=config_data)

    # Parse result
    result = {}
    for line in shell_result.decode('utf8').splitlines():
        if '=' in line: # avoid empty lines.
            key, _, val = line.partition('=')
            result[key] = val.rstrip()

    return result


# Based on readPlist() from
# https://github.com/munki/munki/blob/master/code/client/munkilib/FoundationPlist.py
# Slightly modified method name and variable names to match existing code.
def read_plist(filepath):
    '''
    Read a .plist file from filepath. Return the unpacked root object (which
    is usually a dictionary).
    '''
    plist_data = NSData.dataWithContentsOfFile_(filepath)
    data_object, dummy_plist_format, error = (
        NSPropertyListSerialization.propertyListFromData_mutabilityOption_format_errorDescription_(
            plist_data, NSPropertyListMutableContainers, None, None))
    if data_object is None:
        if error:
            error = error.encode('ascii', 'ignore')
        else:
            error = "Unknown error"
        errmsg = "%s in file %s" % (error, filepath)
        raise NSPropertyListSerializationException(errmsg) # pylint: disable=E0602
    else:
        return data_object


def select_queue(args):
    '''Returns either a print queue to add, or the result of a dialog window.'''
    printer_list = generate_available_queue_list(args)

    # Determine if a pre-selected print queue was passed and is available
    if args.preselected_queue and args.preselected_queue in printer_list:
        return args.preselected_queue

    if not printer_list:
        return display_message_dialog("All available print queues are already installed.")

    return display_queue_selection_dialog(args)


def setup_arg_parser():
    '''Set up argument parser'''
    parser = argparse.ArgumentParser(
        description=("Maps or 'installs' a printer queue after displaying a "
                     "list of available printer queues to the user. Can "
                     "specify a preselected_queue as argument 4, a filter key "
                     "as argument 5, and a filter value as arugment 6.")
    )
    parser.add_argument("jamf_mount", type=str, nargs='?',
                        help="Jamf-passed target drive mount point")
    parser.add_argument("jamf_hostname", type=str, nargs='?',
                        help="Jamf-passed computer hostname")
    parser.add_argument("username", type=str, nargs='?',
                        help="Username of user running policy")
    parser.add_argument("preselected_queue", type=str, nargs='?',
                        help="DisplayName of an available queue to map "
                             "without prompting user for selection")
    parser.add_argument("filter_key", type=str, nargs='?',
                        help="Field name of an attribute which you would "
                             "like to filter the available queues base upon")
    parser.add_argument("filter_value", type=str, nargs='?',
                        help="Value to search the provided filter_key "
                             "attribute for")

    return parser


def setup_logger():
    '''Configure the logging handler'''
    # Create a custom logger
    logger = logging.getLogger(__name__)

    # Create handlers
    c_handler = logging.StreamHandler()
    f_handler = logging.FileHandler(CONFIG.get('Log').get('Path'))

    if CONFIG.get('Log').get('Debug', False):
        logger.setLevel(logging.DEBUG)
    else:
        c_handler.setLevel(logging.WARNING)
        f_handler.setLevel(logging.ERROR)

    # Create formatters and add it to handlers
    c_format = logging.Formatter('%(levelname)s - %(funcName)s() - %(message)s')
    f_format = logging.Formatter('%(asctime)s - %(levelname)s - %(funcName)s() - %(message)s')
    c_handler.setFormatter(c_format)
    f_handler.setFormatter(f_format)

    # Add handlers to the logger
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)

    return logger


def main():
    """Manage arguments and run workflow"""
    # Parse script parameters
    parser = setup_arg_parser()
    args, _ = parser.parse_known_args()

    # Select a queue to add
    selected_queue = select_queue(args)

    # Install the selected printer
    if selected_queue:
        install_printer(selected_queue)


if __name__ == '__main__':
    # Configure the logger
    LOGGER = setup_logger()

    main()
