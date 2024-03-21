import os
import json

from pymodsec import PyModSecurity
from data_loader import DataLoader


ROOT_PATH        = "."
CRS_RULES_DIR    = "./coreruleset/rules/"
MODELS_BASE_PATH = ""
DATASET_PATH     = '../modsec-test-dataset/'

def read_file(file_path, is_json=False):
    try:
        with open(file_path, 'r') as fp:
            if is_json:
                data = json.load(fp)
            else:
                data = fp.read()
    except FileNotFoundError:
        raise SystemExit("{} not found".format(file_path))
    
    except OSError:
        raise SystemExit("Error reading the file {}".format(file_path))
    
    except json.JSONDecodeError:
        raise SystemExit("Cannot decode JSON file: {}".format(file_path))
    
    else:
        return data

import numpy as np
if __name__ == '__main__':

    loader = DataLoader(
        malicious_path = os.path.join(DATASET_PATH, 'malicious/sqli'),
        legitimate_path = os.path.join(DATASET_PATH, 'legitimate/legitimate')
    )

    data = loader.load_data()

    owasp_crs_rules_ids_path = os.path.join(ROOT_PATH, 'owasp_crs_sqli_rules_ids.json')
    owasp_crs_ids = read_file(owasp_crs_rules_ids_path, is_json=True)['rules_ids']

    waf = PyModSecurity(
        rules_dir=CRS_RULES_DIR,
        threshold=5.0,
        pl=4,
        output_type='binary'
    )

    scores = waf.predict(data['payloads'][:10_000])

    print(scores)