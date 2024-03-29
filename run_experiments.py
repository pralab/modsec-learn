import os
import numpy as np
import matplotlib.pyplot as plt

from src.models import PyModSecurity
from src.data_loader import DataLoader
from src.extractor import ModSecurityFeaturesExtractor
from src.utils.plotting import plot_roc
from sklearn.model_selection import train_test_split
from sklearn.svm import LinearSVC
from sklearn.metrics import roc_curve, roc_auc_score, auc
from sklearn.utils import shuffle
from sklearn.ensemble import RandomForestClassifier


ROOT_PATH        = "./data/"
CRS_RULES_DIR    = "./coreruleset/rules/"
MODELS_BASE_PATH = ""
DATASET_PATH     = '../modsec-test-dataset/'


extract_ids = False
paranoia_levels = [1, 2, 3, 4]
models = ['svc', 'rf', 'modsec']


if __name__ == '__main__':
    
    # LOAD DATASET
    print('[INFO] Loading dataset...')
    loader = DataLoader(
        malicious_path  = os.path.join(DATASET_PATH, 'malicious/sqli_14'),
        legitimate_path = os.path.join(DATASET_PATH, 'legitimate/legitimate_7')
    )    
    data = loader.load_data()
    data = shuffle(data)

    fig, axs = plt.subplots(2, 2)
    
    for pl in paranoia_levels:
        # FEATURE EXTRACTION 
        print('[INFO] Extracting features for PL {}...'.format(pl))
        extractor = ModSecurityFeaturesExtractor(
            crs_ids_path = os.path.join(ROOT_PATH, 'crs_sqli_ids_4.0.0.json'),
            crs_path     = CRS_RULES_DIR,
            crs_pl       = pl
        )
    
        X, y = extractor.extract_features(data)

        xtr, xts, ytr, yts = \
            train_test_split(X, y, test_size=0.2, random_state=77, shuffle=False)
                
        # TRAINING / PREDICTION
        for model_name in models:
            print('[INFO] Evaluating {} model for PL {}...'.format(model_name, pl))
            
            if model_name == 'svc':
                model = LinearSVC(
                    class_weight  = 'balanced',
                    random_state  = 77,
                    fit_intercept = False,
                )
                model.fit(xtr, ytr)
                y_preds  = model.predict(xts)
                y_scores = model.decision_function(xts)
            
            elif model_name == 'rf':
                model = RandomForestClassifier(
                    class_weight = 'balanced',
                    random_state = 77,
                    n_jobs       = -1
                )
                model.fit(xtr, ytr)
                y_preds  = model.predict(xts)
                y_scores = model.predict_proba(xts)[:, 1]

            elif model_name == 'modsec':
                waf = PyModSecurity(
                    rules_dir = CRS_RULES_DIR,
                    pl        = pl
                )
                xts_size = len(data) - len(xts)
                y_scores = waf.predict(data['payloads'][xts_size:]) 
            
            plot_roc(
                yts, 
                y_scores, 
                label_legend       = model_name.upper(),
                ax                 = axs.flatten()[pl-1],
                plot_rand_guessing = False,
                log_scale          = True ,
                legend_settings    = {'loc': 'lower right'},
                update_roc_values  = True if pl == 1 else False
            )

    # Final settings for the plot
    for idx, ax in enumerate(axs.flatten()):
        ax.set_title('PL {}'.format(idx+1), fontsize=16)
        ax.xaxis.set_tick_params(labelsize=14)
        ax.yaxis.set_tick_params(labelsize=14)
        ax.xaxis.label.set_size(16)
        ax.yaxis.label.set_size(16)
    
    fig.set_size_inches(9, 9)
    fig.tight_layout()

    plt.show()