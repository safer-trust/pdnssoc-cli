import os
import socket
import json
import logging
import smtplib
import requests
import jinja2
import hashlib
from datetime import timedelta
import pytz
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from pdnssoccli.utils.time import parse_rfc3339_ns

logger = logging.getLogger("pdnssoccli")

def sha256_hash(text):
    sha256 = hashlib.sha256()
    sha256.update(text.encode('utf-8'))
    return sha256.hexdigest()


def alerts_from_file(file_iter, client_hash):
    for match in file_iter:
#        try:
#            match = json.loads(line.strip())
#        except json.JSONDecodeError:
#            logger.warning("Ignoring line due to unrecognized format:{}".format(line))
#            continue

        timestamp = parse_rfc3339_ns(match['timestamp'])

        # Define the client
        # If client_ip exists then
        client_name = match['client_name']
        client_ip = match['client_ip']

        client_hash.setdefault(client_name, {})
        client_hash[client_name].setdefault(client_ip, {})

        client_hash[client_name][client_ip].setdefault(match['query'], {'first_occurence': timestamp, 'events':{}, 'answers': set()})

        # Handle MISP events
        for event in match['correlation']['misp']['events']:

            client_hash[client_name][client_ip][match['query']]['events'][event['uuid']] = event

            # Signify matching IOC

            for answer in match['answers']:
                   client_hash[client_name][client_ip][match['query']]['answers'].add(
                        "{} ({})".format(
                            answer['rdata'],
                            answer['rdatatype']
                        )
                    )

                #client_hash[client_name][client_ip][event['ioc']]['query'].append("match['query']")

            if client_hash[client_name][client_ip][match['query']]['first_occurence'] > timestamp:
                client_hash[client_name][client_ip][match['query']]['first_occurence'] = timestamp
    return client_hash


# Add a hash of new alerts in a file if they are new
def register_new_alert(alerts_database, alerts_database_max_size, alert):
    try:
      with open(alerts_database, 'r+') as file:
        hashes = file.read().splitlines()
        if alert not in hashes:
            logger.debug("Registering new alert in {} : {}".format(alerts_database, alert))
            try:
                # Trim the database if it is bigger than its max size and add our alert 
                if len(hashes) >= alerts_database_max_size:
                    hashes = hashes[-(alerts_database_max_size - 1):]
                hashes.append(alert)
                file.seek(0)
                file.truncate()
                file.write('\n'.join(hashes) + '\n')
                return True
            except IOError as e:
                logger.warn("Error writing to {}: {}".format(filename. e))
                return False
            return True
      return False
    except IOError as e:
        logger.warn("Error accessing file {}: {}".format(filename. e))
        return False
    return False

def if_alert_exists(alerts_database, alert):
    with open(alerts_database, 'r') as file:
        hashes = set(file.read().splitlines())
    return alert in hashes

def slack_alerts(alerts, config, alerts_database, alerts_database_max_size):
#    logger.warn("Slack hook {}".format(config['slack_hook']))

    if not alerts:
        logger.info("No alerts to dispatch")
        return None
    logger.info("Number of pending alerts: {}".format(len(alerts)))
        
    for match in alerts:

        # First, make sure we are not about to create a duplicate alert
        # ['timestamp'][:-1][:11] means we truncate to the date. Not ideal...
        alert_pattern  = sha256_hash(match['client_name'] + match['query'] + match['timestamp'][:-1][:11])

        if if_alert_exists(alerts_database, alert_pattern):
            logger.debug("Redundant alert, stopping: {}".format(alert_pattern))
            continue 
        # For each alert, produce a Slack message:
        logger.debug("Preparing an alert for: {}".format(alert_pattern))
        msg = ""

        # Parsing DNS answers (IP addresses)
        answer = ""
        for new_answer in match['answers']:
            answer += new_answer['rdata'] + ", "
        if answer.endswith(", "):
            answer = answer[:-2]

        #logger.info("Answer: {}".format(answer))

        # Parsing MISP event(s) associate with the IOC
        misp_events = ""
        misp_tags = ""
        misp_ioc = ""
        misp_ioc_addition = ""
        
        if 'correlation' in match and 'misp' in match['correlation'] and 'events' in match['correlation']['misp']:
            events = match['correlation']['misp']['events']
            if events:
                for event in events:
                    misp_events += "[" + event.get('organization') + "] "
                    misp_events += "<" + event.get('event_url') + "|" + event.get('info')  + ">\n"

                    
                    # Extract the 3 first tags of each event associated with the IOC
                    tags = event.get('tags', [])
                    for tag in tags[:3]:
                        misp_tags += tag['name'].replace('"', '\\"') + ", "  

                # formatting the collected data

                if misp_tags.endswith(", "):
                    misp_tags = misp_tags[:-2]        

                misp_ioc += "`" + event.get('ioc').replace('.', '[.]') + "` (" + event.get('ioc_type') + ")\n"
                misp_ioc_addition += "- *MISP IOC date*: " + event.get('publication') + "\n"
                if event.get('comment'):
                    misp_ioc_addition += "- *MISP IOC Comment*: " + event.get('comment') + "\n"
            else:
                misp_events = "[No MISP event found]\n"
        else:
            print("No correlation data found.")


        # Assembling our Slack message
        msg += misp_events
        if misp_tags:
            msg += "*tags*: \"" + misp_tags + "\"\n"
        if misp_ioc:
            msg += "- *IOC*: " + misp_ioc 
        msg += misp_ioc_addition
        msg += "\n*Detection*:\n"
        msg += "*Timestamp:* " + match['timestamp'] + "\n"
        #msg += "*Client:* `" + match['client_name'] + "` (`" + match['client_ip'] + "`)\n"
        try:
                msg += "*Client:* `" + socket.gethostbyaddr(match['client_ip'])[0] + "` (`" + match['client_ip'] + "`)\n"

        except Exception as e:
                logger.info("Could not reverse-resolve {}: {}".format(match['client_ip'], e))
                msg += "*Client:* `" + match['client_ip'] + "`\n"

        msg += "*Query:* `" + match['query'].replace('.', '[.]') + "`\n"
        msg += "*Answer:* `" + answer.replace('.', '[.]') + "`\n"

        logger.debug("MSG: {}".format(msg))
        logger.info("Alerting about {} resolving {}".format(match['client_ip'], match['query'])) 
        # SENDING!

        payload = {"text": f":unicorn_face: [pDNSSOC]: {msg}"}
        headers = {"Content-type": "application/json"}


        try:
            response = requests.post(config['slack_hook'], headers=headers, json=payload)
            logger.debug("Slack: {} - {}".format(response.status_code, response.text))
            response.raise_for_status()  # This will raise an HTTPError if the response was an HTTP error


            # If the request worked, then register the alert in our "database" to avoir duplicate alerts
            register_new_alert(alerts_database, alerts_database_max_size, alert_pattern)


        except requests.exceptions.RequestException as e:
            logger.warn("Slack post failed: {}".format(e))

def email_alerts(alerts, config, summary = False):

    if not alerts:
        logger.debug("No alerts to dispatch")
        return None
    # Define a custom filter to enumerate elements
    def enumerate_filter(iterable):
        return enumerate(iterable, 1)  # Start counting from 1
    # Connecting to the mail server
    smtp = smtplib.SMTP(config['server'], config['port'])

    template_file = Path(config['template'])

    # Set up template
    email_template_loader = jinja2.FileSystemLoader(searchpath = template_file.parent)
    email_template_env = jinja2.Environment(loader = email_template_loader)
    # To allow the use of the timedelta and pytz inside the Jinja2 templates
    email_template_env.globals.update(timedelta = timedelta)
    email_template_env.globals.update(pytz = pytz)
    # Add the custom filter to the Jinja2 environment
    email_template_env.filters['enumerate'] = enumerate_filter

    email_template = email_template_env.get_template(template_file.name)

    outgoing_mailbox = []

    if summary:
        # Load all alerts in one template
        email_body = email_template.render(alerts=alerts)

        msg_root = MIMEMultipart('related')
        msg_root['Subject'] = str(config["subject"])
        msg_root['From'] = config["from"]
        msg_root['To'] = config["summary_to"]
        msg_root['Reply-To'] = config["from"]
        msg_root.preamble = 'This is a multi-part message in MIME format.'
        msg_alternative = MIMEMultipart('alternative')
        msg_root.attach(msg_alternative)
        msg_text = MIMEText(str(email_body), 'html', 'utf-8')
        msg_alternative.attach(msg_text)

        outgoing_mailbox.append(msg_root)

    else:
        # Group emails per destination in email.mappings
        for sensor, sensor_data in alerts.items():
            if sensor in config['mappings']:
                email_body = email_template.render(alerts={sensor:sensor_data})
                msg_root = MIMEMultipart('related')
                msg_root['Subject'] = str(config["subject"])
                msg_root['From'] = config["from"]
                msg_root['To'] = config["mappings"][sensor]['contact']
                msg_root['Reply-To'] = config["from"]
                msg_root.preamble = 'This is a multi-part message in MIME format.'
                msg_alternative = MIMEMultipart('alternative')
                msg_root.attach(msg_alternative)
                msg_text = MIMEText(str(email_body), 'html', 'utf-8')
                msg_alternative.attach(msg_text)

                outgoing_mailbox.append(msg_root)
            else:
                logger.warning("Sensor {} not configured for email alerting".format(sensor))



    for mail in outgoing_mailbox:
        # Send the email
        smtp.sendmail(mail['From'], mail['To'], mail.as_string())
        logging.debug('Sending email notification to {}'.format(mail['To']))

    smtp.quit()
