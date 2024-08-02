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

    alerting_config = ctx.obj['CONFIG']['alerting']
    correlation_config = ctx.obj['CONFIG']['correlation']
    alerts_database = correlation_config['alerts_database']
    alerts_database_max_size = correlation_config['alerts_database_max_size']

    # iterate through alert configs enabled
    for alert_type, alert_conf in ctx.obj['CONFIG']['alerting'].items():
        logger.debug("Alerting via {}".format(alert_type))
        # Set up mailing here


    if not kwargs.get('files'):
        files = [correlation_config['output_dir']]
    else:
        files = kwargs.get('files')

    pending_alerts = {}
    for file in files:
        file_path = Path(file)
        if file_path.is_file():
            file_iter, _ =  pdnssoc_file_utils.read_file(file_path, delete_after_read=False)
            if file_iter:
                try:
                    
                    if alert_type == "slack":
                        pdnssoc_alerting_utils.slack_alerts(file_iter, alerting_config['slack'], alerts_database, alerts_database_max_size)


                    # Honestly not sure what this really does. Seems related to producing a client hash?
                    pending_alerts = pdnssoc_alerting_utils.alerts_from_file(
                        file_iter,
                        pending_alerts
                    )

                except:
                    logger.error("Failed to parse {}, skipping".format(file))
                    continue
            logger.debug("Deleting content of: {}".format(file_path))
            with open(file_path, 'w') as file:
                file.write("")  # Write an empty string to the file and automatically close it

        else:
            for nested_path in file_path.rglob('*'):
                if nested_path.is_file():
                    file_iter, _ =  pdnssoc_file_utils.read_file(nested_path, delete_after_read=False)
                    if file_iter:
                        try:
                            
                            if alert_type == "slack":
                                pdnssoc_alerting_utils.slack_alerts(file_iter, alerting_config['slack'], alerts_database, alerts_database_max_size)

                            # Honestly not sure what this really does. Seems related to producing a client hash?
                            pending_alerts = pdnssoc_alerting_utils.alerts_from_file(
                                file_iter,
                                pending_alerts
                            )
                        except:
                            logger.error("Failed to parse {}, skipping".format(nested_path))
                            continue

            logger.debug("Deleting content of {}".format(file_path))
            with open(nested_path, 'w') as file:
                file.write("")  # Write an empty string to the file and automatically close it

    if not len(pending_alerts):
        logger.info("No alert to be sent.")


    if alert_type == "email":

        # Send summary to pdnssoc service maintainers
        pdnssoc_alerting_utils.email_alerts(pending_alerts, alerting_config['email'], summary=True)

        #Send mails to each of the responsibles for a sensor
        pdnssoc_alerting_utils.email_alerts(pending_alerts, alerting_config['email'], summary=False)

    


