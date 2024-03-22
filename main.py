import os
import json

from src.models import PyModSecurity
from src.data_loader import DataLoader
from src.extractor import ModSecurityFeaturesExtractor


ROOT_PATH        = "."
CRS_RULES_DIR    = "./coreruleset/rules/"
MODELS_BASE_PATH = ""
DATASET_PATH     = '../modsec-test-dataset/'


if __name__ == '__main__':

    loader = DataLoader(
        malicious_path = os.path.join(DATASET_PATH, 'malicious/sqli'),
        legitimate_path = os.path.join(DATASET_PATH, 'legitimate/legitimate')
    )

    data = loader.load_data()[:5000]

    extractor = ModSecurityFeaturesExtractor(
        crs_rules_ids_path=os.path.join(ROOT_PATH, 'crs_sqli_rules_ids.json'),
        crs_rules_path=CRS_RULES_DIR,
        crs_threshold=5.0,
        crs_pl=4
    )

    extractor.extract_crs_ids(data)
    X, y = extractor.extract_features(data)

    print(X.shape)
    print(y.shape)




    # owasp_crs_rules_ids_path = os.path.join(ROOT_PATH, 'owasp_crs_sqli_rules_ids.json')
    # owasp_crs_ids = read_file(owasp_crs_rules_ids_path, is_json=True)['rules_ids']

    # waf = PyModSecurity(
    #     rules_dir=CRS_RULES_DIR,
    #     threshold=5.0,
    #     pl=4,
    #     output_type='binary'
    # )

    # scores = waf.predict(data['payloads'][:10_000])

    # print(scores)