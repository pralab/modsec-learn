import os

from src.data_loader import DataLoader
from src.extractor import ModSecurityFeaturesExtractor
from sklearn.utils import shuffle


if __name__ == '__main__':
    
    # LOAD DATASET
    loader = DataLoader(
        malicious_path  = os.path.join(DATASET_PATH, 'malicious/sqli'),
        legitimate_path = os.path.join(DATASET_PATH, 'legitimate/legitimate')
    )    

    data = loader.load_data()   
    data = shuffle(data)   

    # COMPUTE RULES IDS
    extractor = ModSecurityFeaturesExtractor(
        crs_ids_path = os.path.join(ROOT_PATH, 'crs_sqli_ids_4.0.0.json'),
        crs_path     = CRS_RULES_DIR,
    )

    extractor.extract_crs_ids(data)