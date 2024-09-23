from datetime import datetime, timedelta
from pathlib import Path
from pdnssoccli.utils.file import read_file
import re
from dateutil.relativedelta import relativedelta

def parse_rfc3339_ns(timestamp):
    # Split the timestamp at the decimal point, if present
    parts = timestamp.strip().split('.')

    # Parse the datetime part as a datetime object
    dt = datetime.fromisoformat(parts[0])

    # Initialize nanoseconds to zero
    nanoseconds = 0

    # Handle the nanoseconds part (if present)
    if len(parts) > 1:
        nanoseconds_str = parts[1][:-1]

        # Convert nanoseconds to an integer (padded with zeros)
        nanoseconds = int(nanoseconds_str.ljust(9, '0')[:9])

    # Add nanoseconds to the datetime object
    dt = dt.replace(microsecond=nanoseconds // 1000)  # Convert nanoseconds to microseconds

    return dt

def get_time_from_pointer(path):
    pointer_path = Path(path)
    if pointer_path.is_file():
        pointer_file , _  = read_file(pointer_path)
        for line in pointer_file:
            timestamp = parse_rfc3339_ns(line)
            pointer_dt = timestamp
            return pointer_dt
    return None


TIME_UNITS = {
    'S': lambda n: timedelta(seconds=n),
    'M': lambda n: timedelta(minutes=n),
    'h': lambda n: timedelta(hours=n),
    'd': lambda n: timedelta(days=n),
    'w': lambda n: timedelta(weeks=n),
    'm': lambda n: relativedelta(months=n),
    'Y': lambda n: relativedelta(years=n)
}

def calculate_delta(number, unit):
    if unit in TIME_UNITS:
        return TIME_UNITS[unit](int(number))
    return None
    
def convert_date_to_timestamp(date_filter):
    # Handle None or empty string
    if not date_filter:
        return None
    
    # Current datetime
    now = datetime.now()
    
    # If the input is a single range, e.g., '7d' or '1mo'
    match = re.match(r"(\d+)([SMhdwmY])", date_filter)
    if match:
        number, unit = match.groups()
        delta = calculate_delta(number, unit)
        return int((now - delta).timestamp()) if delta else None

    # If the input is a list or range of time filters, e.g., '[14d, 7d]'
    if date_filter.startswith('[') and date_filter.endswith(']'):
        range_values = re.findall(r"(\d+)([MShdwmY])", date_filter)
        if len(range_values) == 2:
            start_number, start_unit = range_values[0]
            end_number, end_unit = range_values[1]
            
            start_delta = calculate_delta(start_number, start_unit)
            end_delta = calculate_delta(end_number, end_unit)

            start_timestamp = now - start_delta
            end_timestamp = now - end_delta
            return [int(start_timestamp.timestamp()), int(end_timestamp.timestamp())]

    # If the input is a specific timestamp
    try:
        return int(datetime.strptime(date_filter, "%Y-%m-%d %H:%M:%S").timestamp())
    except ValueError:
        pass

    return None
