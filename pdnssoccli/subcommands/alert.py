import click
from datetime import datetime
import ipaddress
from pdnssoccli.subcommands.utils import make_sync
from pdnssoccli.utils import file as pdnssoc_file_utils
from pdnssoccli.utils import time as pdnssoc_time_utils
from pdnssoccli.utils import alert as pdnssoc_alerting_utils
import logging
import jsonlines
from pymisp import PyMISP
from pathlib import Path
import shutil

logger = logging.getLogger(__name__)

@click.command(help="Raise alerts for spotted incidents")
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
@click.pass_context
def alert(ctx,
    **kwargs):

    correlation_config = ctx.obj['CONFIG']['correlation']
    alerts_database = correlation_config['alerts_database']
    alerts_database_max_size = correlation_config['alerts_database_max_size']

    # iterate through alert configs enabled
    alert_map = {}
    for alert_type, alert_conf in ctx.obj['CONFIG']['alerting'].items():
        logger.debug("Alerting via {}".format(alert_type))
        alert_map[alert_type] = alert_conf


    if not kwargs.get('file'):
        file = correlation_config['output_file']
    else:
        file = kwargs.get('file')

    pending_alerts = {}
    file_path = Path(file)
    if file_path.is_file():
        file_iter, _ =  pdnssoc_file_utils.read_file(file_path, delete_after_read=False)
        if file_iter:
            pdnssoc_alerting_utils.send_alerts(file_iter, alert_map, alerts_database, alerts_database_max_size)
            pending_alerts = pdnssoc_alerting_utils.alerts_from_file(file_iter,pending_alerts)

        logger.debug("Deleting content of: {}".format(file_path))
        with open(file_path, 'w') as file:
            file.write("")  # Write an empty string to the file and automatically close it
    else:
        logger.error("Failed to parse {}, skipping".format(file))
    if not len(pending_alerts):
        logger.info("No alert to be sent.")

    if "email" in alert_map:
        # Send summary to pdnssoc service maintainers
        pdnssoc_alerting_utils.email_alerts(pending_alerts, alert_map['email'], summary=True)

        #Send mails to each of the responsibles for a sensor
        pdnssoc_alerting_utils.email_alerts(pending_alerts, alert_map['email'], summary=False)

    


