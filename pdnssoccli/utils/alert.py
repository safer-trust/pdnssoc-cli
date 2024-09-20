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
        timestamp = parse_rfc3339_ns(match['timestamp'])

        # Define the client
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

def parse_msg(path, variables):
    # Define the custom enumerate filter for Jinja2
    def enumerate_filter(iterable):
        return enumerate(iterable, 1)

    # Path to the template file
    template_file = Path(path)

    # Set up Jinja2 environment and loader
    template_loader = jinja2.FileSystemLoader(searchpath=template_file.parent)
    template_env = jinja2.Environment(loader=template_loader)
    # To allow the use of the timedelta and pytz inside the Jinja2 templates
    template_env.globals.update(timedelta = timedelta)
    template_env.globals.update(pytz = pytz)
    # Add the custom filter to the Jinja2 environment
    template_env.filters['enumerate'] = enumerate_filter

    # Load the template
    template = template_env.get_template(template_file.name)
    try:
        msg = template.render(variables)
    except:
        msg = template.render(alerts=variables)

    return msg


def buil_msg(path, match):
    # Parsing DNS answers (IP addresses)
    answer = ""
    for new_answer in match['answers']:
        answer += new_answer['rdata'] + ", "
    if answer.endswith(", "):
        answer = answer[:-2]
    
    # Load all alerts in one template
    context = {
        'events': match['correlation']['misp']['events'],
        'match': match,
        'answer': answer,
        'socket': socket,  # Passing the socket module to use within the template
    }
    
    msg = parse_msg(path, context)
    return msg
    
def send_alerts(alerts, alert_map, alerts_database, alerts_database_max_size):
#    logger.warn("Slack hook {}".format(config['slack_hook']))

    if not alerts:
        logger.info("No alerts to dispatch")
        return None
    logger.info("Number of pending alerts: {}".format(len(alerts)))
        
    for match in alerts:
        # First, make sure we are not about to create a duplicate alert
        # ['timestamp'][:-1][:11] means we truncate to the date. Not ideal...
        alert_pattern  = sha256_hash(match['client_name'] + match['query'] + match['timestamp'][:-1][:16])

        if if_alert_exists(alerts_database, alert_pattern):
            logger.debug("Redundant alert, stopping: {}".format(alert_pattern))
            continue 
        # For each alert, produce a Slack message:
        logger.debug("Preparing an alert for: {}".format(alert_pattern))

        for alert_type, alert_conf in alert_map.items():
            if alert_type == "email":
                continue
            msg = buil_msg(alert_conf["template"], match)

            logger.info("Alerting about {} resolving {}".format(match['client_ip'], match['query'])) 
            
            if alert_type == "slack" or alert_type == "mattermost":
                headers = {"Content-type": "application/json"}
                try:
                    payload = {'text': msg}
                    response = requests.post(alert_conf["hook"], headers=headers, json=payload)
                    logger.debug("Slack/Mattermost: {} - {}".format(response.status_code, response.text))
                    response.raise_for_status()  # This will raise an HTTPError if the response was an HTTP error
                except requests.exceptions.RequestException as e:
                    logger.warn("Slack post failed: {}".format(e))
                    
            elif alert_type == "telegram":
                payload = {'chat_id': alert_conf['telegram_chat_id'], 'text': msg}
                telegram_url = f"https://api.telegram.org/bot{alert_conf['telegram_bot_token']}/sendMessage"
    
                try:
                    response = requests.post(telegram_url, data=payload)
                    logger.debug("Telegram: {} - {}".format(response.status_code, response.text))
                    response.raise_for_status()  # This will raise an HTTPError if the response was an HTTP error
                except requests.exceptions.RequestException as e:
                    logger.warn("Telegram post failed: {}".format(e))

        # If the request worked, then register the alert in our "database" to avoir duplicate alerts
        register_new_alert(alerts_database, alerts_database_max_size, alert_pattern)


def email_alerts(alerts, config, summary = False):

    if not alerts:
        logger.debug("No alerts to dispatch")
        return None
    # Define a custom filter to enumerate elements
    def enumerate_filter(iterable):
        return enumerate(iterable, 1)  # Start counting from 1
    # Connecting to the mail server
    smtp = smtplib.SMTP(config['server'], config['port'])

    

    outgoing_mailbox = []

    if summary:
        # Load all alerts in one template
        email_body = parse_msg(config["template"], alerts)

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
            for mapping in config['mappings']:
                if sensor == mapping["client_id"]:
                    alerts={sensor:sensor_data}
                    email_body = parse_msg(config["template"], alerts)
                    msg_root = MIMEMultipart('related')
                    msg_root['Subject'] = str(config["subject"])
                    msg_root['From'] = config["from"]
                    msg_root['To'] = mapping['contact']
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
