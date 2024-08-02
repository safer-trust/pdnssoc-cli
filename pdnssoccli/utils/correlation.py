import json
import ipaddress
import logging
from . import time as pdnssoc_time_utils
from cachetools import cached
from cachetools.keys import hashkey
import pytz

logger = logging.getLogger("pdnssoccli")

@cached(cache={}, key=lambda query, domain_set: hashkey(query))
def correlate_query(query, domain_set):
    if query in domain_set:
        return True
    else:
        return False

@cached(cache={}, key=lambda answer, ip_set: hashkey(answer['rdata']))
def correlate_answer(answer, ip_set):
    if answer['rdatatype'] == 'A' or answer['rdatatype'] == 'AAAA':
        ip_answer = ipaddress.ip_address(answer['rdata'])
        for network in ip_set:
            if ip_answer in network:
                return True
    return False


def correlate_events(lines, shared_data):
    (domain_attributes, ip_attributes, domain_attributes_metadata, ip_attributes_metadata, is_minified) = shared_data
    total_matches = []
    for match in lines:
    # Extract the timestamp, query and answers

# Maybe add the following to file.py?
#        try:
#          #match = json.loads(line)
#        except json.JSONDecodeError:
#            logger.debug("Ignoring line due to unrecognized format:{}".format(line))
#            continue
        
        if is_minified:
            timestamp = pdnssoc_time_utils.parse_rfc3339_ns(match['timestamp'])
            query = match['query']
            answers = match['answers']
        else:
            # Regular correlation
            timestamp = pdnssoc_time_utils.parse_rfc3339_ns(
                match['dnstap']["timestamp-rfc3339ns"]
            )
            query = match['dns']['qname']
            answers = match['dns']['resource-records']['an']

        logger.debug("time: {}, qname: {}".format(timestamp, query))
        # parse timestamp
        if correlate_query(query, domain_attributes):
            if domain_attributes_metadata: # retro mode
                if domain_attributes_metadata[query] > pytz.utc.localize(timestamp) and (not retro_last_date or domain_attributes_metadata[query] > pytz.utc.localize(retro_last_date)):
                    total_matches.append(match)
                    continue
            else:
                logging.debug("Matched {}".format(match))
                total_matches.append(match)
                continue

        for answer in answers:
            if correlate_answer(answer, ip_attributes):
                if ip_attributes_metadata: # retro mode
                    if ip_attributes_metadata[answer['rdata']] > pytz.utc.localize(timestamp) and (not retro_last_date or ip_attributes_metadata[answer['rdata']] > pytz.utc.localize(retro_last_date)):
                        total_matches.append(match)
                        continue
                else:
                    total_matches.append(match)
                break

    return total_matches

def correlate_file(file_iter, domain_attributes, ip_attributes, domain_attributes_metadata, ip_attributes_metadata, is_minified):
    total_matches = []
    total_matches = correlate_events(file_iter, (domain_attributes, ip_attributes, domain_attributes_metadata, ip_attributes_metadata, is_minified))
    return total_matches
