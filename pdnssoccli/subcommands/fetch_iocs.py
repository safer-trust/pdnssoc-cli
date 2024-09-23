import click
from datetime import timedelta, datetime
import logging
from pymisp import PyMISP
from pathlib import Path
from pdnssoccli.utils import file as pdnssoc_file_utils
from pdnssoccli.utils import time as pdnssoc_time_utils

logger = logging.getLogger(__name__)

@click.command(help="Fetch IOCs from intelligence sources")
@click.option(
    'logging_level',
    '--logging',
    type=click.Choice(['INFO','WARN','DEBUG','ERROR']),
    default="INFO"
)
@click.option(
    'malicious_domains_file',
    '--malicious-domains-file',
    type=click.Path(
        file_okay=True,
        dir_okay=False,
        readable=True
    ),
)
@click.option(
    'malicious_ips_file',
    '--malicious-ips-file',
    type=click.Path(
        file_okay=True,
        dir_okay=False,
        readable=True
    ),
)
@click.pass_context
def fetch_iocs(ctx,
    **kwargs):
    correlation_config = ctx.obj['CONFIG']['correlation']
    TYPE_ATTRIBUTES =[ 'domain', 'domain|ip', 'hostname', 'hostname|port', 'ip-src', 'ip-src|port', 'ip-dst', 'ip-dst|port', ]

    # Set up MISP connections
    for misp_conf in ctx.obj['CONFIG']["misp_servers"]:
        misp = PyMISP(misp_conf['domain'], misp_conf['api_key'], misp_conf['verify_ssl'], debug=misp_conf['debug'])
        tags = None
        if 'tags' in misp_conf['periods'] and misp_conf['periods']['tags']:
            tags = misp_conf['periods']['tags']
    
        args = misp_conf['args']

        domain_attributes_old, domain_attributes_new, ips_attributes_new, ips_attributes_old, attributes = [], [], [], [], []

        # Fetch catch all
        if 'date' in misp_conf['periods'] and misp_conf['periods']["date"]:
            date_search = pdnssoc_time_utils.convert_date_to_timestamp(misp_conf['periods']['date'])
        else:
            # Default search is 30 days
            date_search=pdnssoc_time_utils.convert_date_to_timestamp("30d")

        catch_all_attributes = misp.search(
            controller='attributes',
            type_attribute=TYPE_ATTRIBUTES,
            to_ids=1,
            pythonify=True,
            tags=tags,
            timestamp=date_search,
            **args
        )

        attributes.extend(catch_all_attributes)

        # Get new attributes
        ips_to_validate = set()

        for attribute in attributes:
            # Put to bucket according to attribute type
            if attribute.type == 'domain' or attribute.type == 'hostname':
                domain_attributes_new.append(attribute.value)
            elif attribute.type == 'domain|ip':
                domain_val, ip_val = attribute.value.split("|")
                domain_attributes_new.append(domain_val)
                ips_attributes_new.append(ip_val)
            elif attribute.type == 'hostname|port':
                hostname_val, _ = attribute.value.split("|")
                domain_attributes_new.append(hostname_val)
            elif attribute.type == 'ip-src' or attribute.type == 'ip-dst':
                ips_attributes_new.append(attribute.value)
            elif attribute.type == 'ip-src|port' or attribute.type == 'ip-dst|port':
                ip_val, _ = attribute.value.split("|")
                ips_to_validate.add(ip_val)

        # Validate ip|port attributes against warninglists
        warn_matches = misp.values_in_warninglist(list(ips_to_validate))

        if warn_matches:
            res = [i for i in list(ips_to_validate) if i not in warn_matches.keys()]
            ips_attributes_new.extend(res)

        # Check if domain ioc files already exist
        domains_file_path = correlation_config['malicious_domains_file']
        domains_file = Path(domains_file_path)

        if domains_file.is_file():
            # File exists, let's try to update it
            domains_iter, _ = pdnssoc_file_utils.read_file(Path(correlation_config['malicious_domains_file']), delete_after_read=False)
            for domain in domains_iter:
                domain_attributes_old.append(domain.strip())

        if set(domain_attributes_old) != set(domain_attributes_new):
            # We spotted a difference, let's overwrite the existing file
            with pdnssoc_file_utils.write_generic(domains_file) as fp:
                for attribute in list(set(domain_attributes_new)):
                    fp.write("{}\n".format(attribute))

        # Check if ip ioc files already exist
        ips_file_path = correlation_config['malicious_ips_file']
        ips_file = Path(ips_file_path)

        if ips_file.is_file():
            # File exists, let's try to update it
            ips_iter, _ = pdnssoc_file_utils.read_file(Path(correlation_config['malicious_ips_file']), delete_after_read=False)
            for ip in ips_iter:
                ips_attributes_old.append(ip.strip())

        if set(ips_attributes_old) != set(ips_attributes_new):
            # We spotted a difference, let's overwrite the existing file
            with pdnssoc_file_utils.write_generic(ips_file) as fp:
                for attribute in list(set(ips_attributes_new)):
                    fp.write("{}\n".format(attribute))
            logger.info("Loaded {} domains and {} ips".format(len(set(domain_attributes_new).union(set(domain_attributes_new))), len(set(ips_attributes_new).union(set(ips_attributes_old)))))
        else:
            logger.info("All attributes already existed, nothing to add")

        logger.debug("Finished fetching of IOCs")
        if not len(set(domain_attributes_new)):
                logger.error("No domain could be downloaded from MISP!")
