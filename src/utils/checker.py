"""

"""

import os


def type_check(object_to_check, type_to_check, param_name):
    """
    Check if the `object_to_check` is an instance of `type_to_check`.

    Parameters:
    ----------
        object_to_check: object
            The object to check.
        type_to_check: type
            The type to check.
        param_name: str
            The name of the parameter.

    Raises:
    -------
        TypeError: 
            if the `object_to_check` is not an instance of `type_to_check`.
    """
    if not isinstance(object_to_check, type_to_check):
        raise TypeError(
            "{} is not {} but {}".format(
                param_name, type_to_check, type(object_to_check)
            )
        )


def file_exists(file_path: str):
    """
    Check if the file exists.

    Parameters:
    ----------
        file_path: str
            The path to the file.

    Raises:
    -------
        FileNotFoundError:
            if the file does not exist.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError("{} not exists".format(file_path))