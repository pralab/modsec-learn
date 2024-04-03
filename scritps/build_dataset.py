import os
import toml
import sys
import json
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.data_loader import DataLoader
from src.extractor import ModSecurityFeaturesExtractor
from sklearn.utils import shuffle
from sklearn.model_selection import train_test_split


if __name__ == '__main__':
    settings      = toml.load('config.toml')
    crs_dir       = settings['crs_dir']
    crs_ids_path  = settings['crs_ids_path']

    loader = DataLoader(
        malicious_path  = '../modsec-test-dataset/malicious/sqli_dataset.json',
        legitimate_path = '../modsec-test-dataset/legitimate/legitimate_dataset.json'
    )    
    df = loader.load_data()

    legitimate_data = shuffle(
        df[df['labels'] == 0],
        random_state = 77,
        n_samples    = 25_000
    )
    malicious_data  = shuffle(
        df[df['labels'] == 1],
        random_state = 77,
        n_samples    = 25_000
    )

    # LEGITIMATE DATA
    xtr, xts, _, _ = train_test_split(
        legitimate_data['payloads'],
        legitimate_data['labels'],
        test_size    = 0.2,
        random_state = 77,
        shuffle      = True
    )

    with open('data/dataset/legitimate_train.json', 'w') as file:
        json.dump(xtr.tolist(), file, indent=4)

    with open('data/dataset/legitimate_test.json', 'w') as file:
        json.dump(xts.tolist(), file, indent=4)

    # MALICIOUS DATA
    xtr, xts, _, _ = train_test_split(
        malicious_data['payloads'],
        malicious_data['labels'],
        test_size    = 0.2,
        random_state = 77,
        shuffle      = True
    )

    with open('data/dataset/malicious_train.json', 'w') as file:
        json.dump(xtr.tolist(), file, indent=4)

    with open('data/dataset/malicious_test.json', 'w') as file:
        json.dump(xts.tolist(), file, indent=4)