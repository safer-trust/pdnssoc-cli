import click
from datetime import timedelta
from datetime import datetime
import ipaddress
from pdnssoccli.subcommands.utils import make_sync
from pdnssoccli.utils import file as pdnssoc_file_utils
from pdnssoccli.utils import time as pdnssoc_time_utils
from pdnssoccli.utils import correlation as pdnssoc_correlation_utils
from pdnssoccli.utils import enrichment as pdnssoc_enrichment_utils
import logging
import jsonlines
from pymisp import PyMISP
from pathlib import Path
import shutil

logger = logging.getLogger(__name__)

@click.command(help="Correlate input files and output matches")
@click.argument(
    'files',
    nargs=-1,
    type=click.Path(
        file_okay=True,
        dir_okay=True,
        readable=True,
        allow_dash=True
    )
)
@click.option(
    'logging_level',
    '--logging',
    type=click.Choice(['INFO','WARN','DEBUG','ERROR']),
    default="INFO"
)
@click.option(
    'retro_disco_lookup',
    '--retro_disco_lookup',
    is_flag=True,
    help="Correlate retrospectively with up to date IOCs",
    default=False
)
@click.option(
    'correlation_output_file',
    '--output-dir',
    type=click.Path(
        file_okay=False,
        dir_okay=True,
        writable=True,
        allow_dash=True
    )
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
def correlate(ctx,
    **kwargs):

    correlation_config = ctx.obj['CONFIG']['correlation']

    # This is important. By default, we delete the JSON date in the matches.
    # If we run in retro search mode, we keep the file and do not delete it.
    deletemode = True
    if kwargs.get('retro_disco_lookup'):
        logging.info("Retro disco mode.")
        deletemode = False

    # Set up MISP connections
    misp_connections = []
    for misp_conf in ctx.obj['CONFIG']["misp_servers"]:
        misp = PyMISP(misp_conf['domain'], misp_conf['api_key'], ssl=misp_conf['verify_ssl'], debug=misp_conf['debug'])
        if misp:
            misp_connections.append((misp, misp_conf['args']))


    # Set up domain and ip blacklists
    domain_attributes = []
    domain_attributes_metadata = {}
    if 'malicious_domains_file' in correlation_config and correlation_config['malicious_domains_file'] and not kwargs.get('retro_lookup'):
        domains_iter, _ = pdnssoc_file_utils.read_file(Path(correlation_config['malicious_domains_file']), delete_after_read=False)
        for domain in domains_iter:
            domain_attributes.append(domain.strip())
    else:
        for misp, args in misp_connections:
            attributes = misp.search(controller='attributes', type_attribute='domain', to_ids=1, pythonify=True, **args)
            for attribute in attributes:
                domain_attributes.append(attribute.value)
                if kwargs.get('retro_lookup'):
                    if attribute.value in domain_attributes_metadata:
                        if attribute.timestamp > domain_attributes_metadata[attribute.value]:
                            domain_attributes_metadata[attribute.value] = attribute.timestamp
                    else:
                        domain_attributes_metadata[attribute.value] = attribute.timestamp

    domain_attributes = list(set(domain_attributes))

    ip_attributes = []
    ip_attributes_metadata = {}
    if 'malicious_ips_file' in correlation_config and correlation_config['malicious_ips_file'] and not kwargs.get('retro_lookup'):
        ips_iter, _ = pdnssoc_file_utils.read_file(Path(correlation_config['malicious_ips_file']), delete_after_read=False)
        for attribute in ips_iter:
            try:
                network = ipaddress.ip_network(attribute.strip(), strict=False)
                ip_attributes.append(network)
            except ValueError:
                logging.warning("Invalid malicious IP value {}".format(attribute))
    else:
        for misp, args in misp_connections:
            ips_iter = misp.search(controller='attributes', type_attribute=['ip-src','ip-dst'], to_ids=1, pythonify=True, **args)

            for attribute in ips_iter:
                try:
                    network = ipaddress.ip_network(attribute.value, strict=False)
                    ip_attributes.append(network)
                    if kwargs.get('retro_lookup'):
                        if attribute.value in ip_attributes_metadata:
                            if attribute.timestamp > ip_attributes_metadata[attribute.value]:
                                ip_attributes_metadata[attribute.value] = attribute.timestamp
                        else:
                            ip_attributes_metadata[attribute.value] = attribute.timestamp
                except ValueError:
                    logging.warning("Invalid malicious IP value {}".format(attribute.value))

    ip_attributes = list(set(ip_attributes))

    logger.debug("Correlating with {} domains and {} ips".format(len(domain_attributes), len(ip_attributes)))
    total_matches = []
    total_matches_minified = []
    if not kwargs.get('files'):
        files = [correlation_config['input_dir']]
    else:
        files = kwargs.get('files')

    for file in files:
        file_path = Path(file)

        if file_path.is_file():
            logger.debug("Correlating {}".format(file))

            file_iter, is_minified =  pdnssoc_file_utils.read_file(file_path, delete_after_read = deletemode)
            # Now go through the file content and correlate each line  
            if file_iter:
                try:
                    matches = pdnssoc_correlation_utils.correlate_file(
                        file_iter,
                        set(domain_attributes),
                        set(ip_attributes),
                        domain_attributes_metadata,
                        ip_attributes_metadata,
                        is_minified
                    )
                    if is_minified:
                        total_matches_minified.extend(matches)
                    else:
                        total_matches.extend(matches)

                    if len(matches):
                        logger.info("Found {} matches in {}".format(len(matches), file_path.absolute()))
                    else:
                        logger.info("No match found in {}".format(file_path.absolute()))

                except:
                    logger.error("Failed to parse {}, skipping".format(file))
                    continue
            else:
                logger.info("No data in {}".format(file_path))


        else:
            # Recursively handle stuff

            for nested_path in file_path.rglob('*'):
                if nested_path.is_file():
                    file_iter, is_minified =  pdnssoc_file_utils.read_file(nested_path, delete_after_read = deletemode)
                    if file_iter:
                        try:
                            matches = pdnssoc_correlation_utils.correlate_file(
                                file_iter,
                                set(domain_attributes),
                                set(ip_attributes),
                                domain_attributes_metadata,
                                ip_attributes_metadata,
                                is_minified
                            )

                            if len(matches):
                                logger.info("Found {} matches in {}".format(len(matches), nested_path.absolute()))
                                #logger.info("Matches: {}".format(matches['dns']['qname']))
                            else:
                                logger.info("No match found in {}".format(nested_path.absolute()))
                            if is_minified:
                                total_matches_minified.extend(matches)
                            else:
                                total_matches.extend(matches)
                        except:
                            logger.error("Failed to parse {}, skipping".format(nested_path))
                            continue

    if not len(total_matches):
        logger.info("No dnscollector match found.")
    enriched = pdnssoc_enrichment_utils.enrich_logs(total_matches, misp_connections, False)
    enriched_minified = pdnssoc_enrichment_utils.enrich_logs(total_matches_minified, misp_connections, True)

    # Output to directory
    # Write full matches to matches.json

    to_output = enriched + enriched_minified
    to_output = sorted(to_output, key=lambda d: d['timestamp'])

    with jsonlines.open(Path(correlation_config['output_file']), mode='a') as writer:
        for document in to_output:
            writer.write(document)

