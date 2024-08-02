# pdnssoc-cli

Correlate dnstap files with MISP threat intelligence.

This tool parses JSON and compressed files created by [go-dnscollector](https://github.com/dmachard/go-dnscollector).


## Installation

`pdnssoc-cli` can be fetched from the following sources:

### PyPi
```bash
python3 -m venv venv && \
source venv/bin/activate && \ 
pip3 install -U pip

pip3 install git+https://github.com/safer-trust/pdnssoc-cli.git@topic/packaging

```



## Configuration

Configuration can be provided using the ``--config`` flag in yaml format. An example configuration file can be found [here](./config.yml.sample).


If no config flag is provided, the default file is `/etc/pdnssoc-cli/config.yml`.


## Usage

```
Usage: python -m pdnssoccli.pdnssoccli [OPTIONS] COMMAND [ARGS]...

Options:
  -c, --config FILE  Read option defaults from the specified yaml file
                     [default: /etc/pdnssoc-cli/config.yml]
  --help             Show this message and exit.

Commands:
  alert       Raise alerts for spotted incidents
  correlate   Correlate input files and output matches
  daemonize   Run in daemonized mode according to configuration
  fetch-iocs  Fetch IOCs from intelligence sources
```