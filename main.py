import os
import numpy as np

from src.models import PyModSecurity, SklearnModelWrapper
from src.data_loader import DataLoader
from src.extractor import ModSecurityFeaturesExtractor
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.metrics import roc_curve, roc_auc_score, RocCurveDisplay, \
    auc
import matplotlib.pyplot as plt


ROOT_PATH        = "."
CRS_RULES_DIR    = "./coreruleset-4.1.0/rules/"
MODELS_BASE_PATH = ""
DATASET_PATH     = '../modsec-test-dataset/'


if __name__ == '__main__':

    loader = DataLoader(
        malicious_path = os.path.join(DATASET_PATH, 'malicious/sqli'),
        legitimate_path = os.path.join(DATASET_PATH, 'legitimate/legitimate_1')
    )

    data = loader.load_data()

    extractor = ModSecurityFeaturesExtractor(
        crs_rules_ids_path=os.path.join(ROOT_PATH, 'crs_sqli_rules_ids.json'),
        crs_rules_path=CRS_RULES_DIR,
        crs_threshold=5.0,
        crs_pl=4
    )

    extractor.extract_crs_ids(data)
    X, y = extractor.extract_features(data)


    X_train, X_test, y_train, y_test = \
        train_test_split(X, y, test_size=0.2, random_state=42, shuffle=True)

    model = SVC(
        decision_function_shape='ovo',
        probability=True,
    )

    model.fit(X_train, y_train)

    y_preds = model.predict(X_test)
    y_scores = model.decision_function(X_test)

    #fig, ax = plt.subplots(2, 2, figsize=(10, 6))
    #RocCurveDisplay.from_predictions(y_test, y_preds)
    auc = roc_auc_score(y_test, y_scores)
    fpr, tpr, _ = roc_curve(y_test, y_scores)

    plt.plot(fpr, tpr, marker='.', label='SVM (AUC = %0.3f)' %auc)
    plt.plot([0, 1], [0, 1], 'k--', label='Chance')
    plt.show()


    # print(X.shape)
    # print(y.shape)

    # waf = PyModSecurity(
    #     rules_dir=CRS_RULES_DIR,
    #     threshold=5.0,
    #     pl=4,
    #     output_type='binary'
    # )

    # scores = waf.predict(data['payloads'])

    # print(np.count_nonzero(scores == 1))

    # print(scores)