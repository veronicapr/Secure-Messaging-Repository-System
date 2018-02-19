import inspect
import logging
import re


def log(level, message):
    func = inspect.currentframe().f_back.f_code
    if level is logging.INFO:
        logging.log(level, " %20s:%4i: %20s: %s " % (
            re.split("[/\\\]+", func.co_filename)[-1],
            func.co_firstlineno,
            func.co_name,
            message,))
    else:
        logging.log(level, "%20s:%4i: %20s: %s " % (
            re.split("[/\\\]+", func.co_filename)[-1],
            func.co_firstlineno,
            func.co_name,
            message,))
