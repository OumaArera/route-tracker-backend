from datetime import datetime


def rate(response):
    pass

def current_time():
    current_datetime = datetime.now()
    start_of_day = current_datetime.replace(hour=0, minute=0, second=0, microsecond=0)

    print(f"Today is: {current_datetime}")
    print(f"Today started at: {start_of_day}")

current_time()