import logging
import yaml
import time
from datetime import datetime
from libQueryTpot import TPotQuery
import urllib3

def load_config(config_file='config.yml'):
    """
    Load configuration settings from a YAML file.

    Args:
        config_file (str): Path to the config YAML file.

    Returns:
        dict: Parsed configuration.

    Raises:
        FileNotFoundError: If the config file is not found.
        yaml.YAMLError: If the config file is malformed.
    """
    try:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        with open(config_file, 'r') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        logging.error(f"Configuration file '{config_file}' not found.")
        raise
    except yaml.YAMLError as e:
        logging.error(f"Error parsing configuration file: {e}")
        raise

def main():
    """Main entry point for the script."""
    config = load_config()

    # Set up logging
    logging_level = getattr(
        logging,
        config.get('logging', {}).get('level', 'INFO').upper(),
        logging.INFO
    )
    logging.basicConfig(
        filename='./pullTPOTDataForOTX.log',
        level=logging_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    logging.info("Starting TPOT data extraction...")

    # Initialize TPotQuery object
    tpot = TPotQuery(
        es_host=config['elasticsearch']['honeypot_host'],
        index_name=config['elasticsearch']['index_name'],
        api_key_id=config['elasticsearch']['api_key_id'],
        api_key=config['elasticsearch']['api_key'],
        config=config
    )

    # Pull logs from Elasticsearch
    results = tpot.pull_recent_logs(minutes_back=config['elasticsearch']['minutes_back'])

    logging.info(f"Fetched {len(results)} results from Elasticsearch.")

    #tpot.show_results()

    tpot.summarize_type_field(entries=results)
    tpot.summarize_credentials(entries=results)
    tpot.summarize_hashes(entries=results)
    tpot.summarize_inputs(entries=results)

    # Create a date-based string for use in OTX pulse, reports, etc.
    pulse_string = datetime.now().strftime("%B_%Y")
    logging.info(f"Pulse string for current month: {pulse_string}")

if __name__ == "__main__":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    start = time.time()
    try:
        main()
    finally:
        elapsed = time.time() - start
        print(f" [++]: Script executed in {elapsed:.2f} seconds")
        logging.info(f"Script completed in {elapsed:.2f} seconds")
