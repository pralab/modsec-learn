import toml
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.models import PyModSecurity
from src.data_loader import DataLoader
from src.extractor import ModSecurityFeaturesExtractor
from sklearn.model_selection import train_test_split
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.utils import shuffle


if __name__  == '__main__':
    settings         = toml.load('config.toml')
    crs_dir          = settings['crs_dir']
    models_path      = settings['models_path']
    figures_path     = settings['figures_path']
    dataset_path     = settings['dataset_path']
    paranoia_levels  = settings['paranoia_levels']
    models           = settings['models']

    # LOAD DATASET
    print('[INFO] Loading dataset...')
    loader = DataLoader(
        malicious_path  = os.path.join(dataset_path, 'malicious/sqli_14'),
        legitimate_path = os.path.join(dataset_path, 'legitimate/legitimate_7')
    )

    data = loader.load_data()
    data = shuffle(data)