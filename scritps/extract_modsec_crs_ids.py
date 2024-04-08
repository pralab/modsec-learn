"""
This script is used to extract the CRS IDs from the ModSecurity Core Rule Set (CRS)
and save them into a JSON file.
"""

import os
import toml
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.data_loader import DataLoader
from src.extractor import ModSecurityFeaturesExtractor


if __name__ == '__main__':
    settings        = toml.load('config.toml')
    dataset_path    = settings['dataset_path']
    crs_dir         = settings['crs_dir']
    crs_ids_path    = settings['crs_ids_path']
    legitimate_path = settings['legitimate_path']
    malicious_path  = settings['malicious_path']

    # LOADING DATASET PHASE
    print('[INFO] Loading dataset...')

    loader = DataLoader(
        legitimate_path = legitimate_path,
        malicious_path  = malicious_path,
    )     

    data = loader.load_data()   

    # EXTRACTS RULES IDS PHASE
    print('[INFO] Extracting CRS IDs...')

    extractor = ModSecurityFeaturesExtractor(
        crs_ids_path = crs_ids_path,
        crs_path     = crs_dir,
    )

    extractor.extract_crs_ids(data)