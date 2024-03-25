import os
import numpy as np

from src.models import PyModSecurity, SklearnModelWrapper
from src.data_loader import DataLoader
from src.extractor import ModSecurityFeaturesExtractor
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.metrics import roc_curve, roc_auc_score, RocCurveDisplay, \
    auc
from sklearn.utils import shuffle
import matplotlib.pyplot as plt


ROOT_PATH        = "."
CRS_RULES_DIR    = "./coreruleset-4.1.0/rules/"
MODELS_BASE_PATH = ""
DATASET_PATH     = 'modsec-test-dataset/'


if __name__ == '__main__':

    loader = DataLoader(
        malicious_path = os.path.join(DATASET_PATH, 'malicious/sqli'),
        legitimate_path = os.path.join(DATASET_PATH, 'legitimate/legitimate')
    )    

    data = loader.load_data()   
    data = shuffle(data)    
    
    loader_train = DataLoader(
        malicious_path = os.path.join(DATASET_PATH, 'malicious/sqli_10'),
        legitimate_path = os.path.join(DATASET_PATH, 'legitimate/legitimate_5')
    )

    loader_test = DataLoader(
        malicious_path=os.path.join(DATASET_PATH, 'malicious/sqli_10'),     
        legitimate_path=os.path.join(DATASET_PATH, 'legitimate/legitimate_5')
    )
    
    data_train = loader_train.load_data()
    
    data_train = shuffle(data_train)

    data_test = loader_test.load_data()
    data_test = shuffle(data_test)
    
    
    
    extractor = ModSecurityFeaturesExtractor(
        crs_rules_ids_path=os.path.join(ROOT_PATH, 'crs_sqli_rules_ids.json'),
        crs_rules_path=CRS_RULES_DIR,
        crs_threshold=5.0,
        crs_pl=4
    )

    #extractor.extract_crs_ids(data)
    
    
    X_train, y_train = extractor.extract_features(data_train)
    X_test, y_test = extractor.extract_features(data_test)  
    
    
    X_train, _, y_train, _ = \
        train_test_split(X_train, y_train, test_size=0.1, random_state=77, shuffle=False)
    print(X_train.shape)
    
    model = SVC(C=1, 
                kernel='poly', 
        decision_function_shape='ovo',
        probability=False,
    )

    model.fit(X_train, y_train)

    y_preds = model.predict(X_test)
    y_scores = model.decision_function(X_test)
    
    waf = PyModSecurity(
         rules_dir=CRS_RULES_DIR,
         threshold=5.0,
         pl=4,
         output_type='score'
    )

    scores = waf.predict(data['payloads'])[50059:]

    aucml = roc_auc_score(y_test, y_scores)
    aucmod = roc_auc_score(y_test, scores)
    fprml, tprml, _ = roc_curve(y_test, y_scores)
    fprmod, tprmod, _ = roc_curve(y_test, scores)
    fig, axs = plt.subplots(1, 2, figsize=(12, 6))  

    axs[0].plot(fprml, tprml, label=f'SVM (AUC = {aucml:.3f})')
    axs[0].plot(fprmod, tprmod, marker='.', label=f'ModSecurity (AUC = {aucmod:.3f})')
    axs[0].plot([0, 1], [0, 1], 'k--', label='Chance')
    axs[0].set_xlim([-0.05, 1.05])
    axs[0].set_ylim([-0.05, 1.05])
    axs[0].set_xlabel("False Positive Rate (FPR)", fontsize=14)
    axs[0].set_ylabel("True Positive Rate (TPR)", fontsize=14)
    axs[0].set_title("ROC Curve without Log Scale")
    axs[0].legend()


    axs[1].plot(fprml, tprml, label=f'SVM (AUC = {aucml:.3f})')
    axs[1].plot(fprmod, tprmod, marker='.', label=f'ModSecurity (AUC = {aucmod:.3f})')
    axs[1].set_xscale('log')
    axs[1].set_xlim([10e-4, 10e0])
    axs[1].set_ylim([-0.05, 1.05])
    axs[1].set_xticks([10e-4, 10e-3, 10e-2, 10e-1, 10e0])  
    axs[1].get_xaxis().set_major_formatter(plt.ScalarFormatter()) 
    axs[1].set_xlabel("False Positive Rate (FPR)", fontsize=14)

    axs[1].set_title("ROC Curve with Log Scale")
    axs[1].legend()

    plt.tight_layout()  
    plt.savefig('roc_curve_comparison.pdf')
    plt.show()
    

    
   
    
    

    