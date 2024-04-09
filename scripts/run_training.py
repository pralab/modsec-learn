"""
This script is used to train the models with different paranoia levels and penalties.
The trained models are saved as joblib files in the models directory.
"""

import toml
import os
import sys
import joblib
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.data_loader import DataLoader
from src.extractor import ModSecurityFeaturesExtractor
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression


if __name__        == '__main__':
    settings         = toml.load('config.toml')
    crs_dir          = settings['crs_dir']
    crs_ids_path     = settings['crs_ids_path']
    models_path      = settings['models_path']
    figures_path     = settings['figures_path']
    dataset_path     = settings['dataset_path']
    paranoia_levels  = settings['params']['paranoia_levels']
    models           = list(filter(lambda model: model != 'modsec', settings['params']['other_models']))
    models           +=settings['params']['models']
    penalties        = settings['params']['penalties']

    # LOADING DATASET PHASE
    print('[INFO] Loading dataset...')
    
    loader = DataLoader(
        malicious_path  = os.path.join(dataset_path, 'malicious_train.json'),
        legitimate_path = os.path.join(dataset_path, 'legitimate_train.json')
    )    
    training_data = loader.load_data()

    models_weights = dict()
    
    for pl in paranoia_levels:
        # FEATURE EXTRACTION PHASE
        print('[INFO] Extracting features for PL {}...'.format(pl))
        
        extractor = ModSecurityFeaturesExtractor(
            crs_ids_path = crs_ids_path,
            crs_path     = crs_dir,
            crs_pl       = pl
        )
    
        xtr, ytr = extractor.extract_features(training_data)

        # TRAINING PHASE
        for model_name in models:
            print('[INFO] Training {} model for PL {}...'.format(model_name, pl))
            
            if model_name == 'svc':
                for penalty in penalties:
                    model = LinearSVC(
                        C             = 0.5,
                        penalty       = penalty,
                        dual          = False,
                        class_weight  = 'balanced',
                        random_state  = 77,
                        fit_intercept = False,
                        max_iter      = 1000
                    )
                    model.fit(xtr, ytr)

                    joblib.dump(
                        model, 
                        os.path.join(models_path, 'linear_svc_pl{}_{}.joblib'.format(pl, penalty))
                    )
                
            elif model_name == 'rf':
                model = RandomForestClassifier(
                    class_weight = 'balanced',
                    random_state = 77,
                    n_jobs       = -1
                )
                model.fit(xtr, ytr)

                joblib.dump(
                    model, 
                    os.path.join(models_path, 'rf_pl{}.joblib'.format(pl))
                )

            elif model_name == 'log_reg':
                for penalty in penalties:
                    model = LogisticRegression(
                        C            = 0.5,
                        penalty      = penalty,
                        dual         = False,
                        class_weight = 'balanced',
                        random_state = 77,
                        n_jobs       = -1,
                        max_iter     = 1000,
                        solver       = 'saga'
                    )
                    model.fit(xtr, ytr)

                    joblib.dump(
                        model, 
                        os.path.join(models_path, 'log_reg_pl{}_{}.joblib'.format(pl, penalty))
                    )