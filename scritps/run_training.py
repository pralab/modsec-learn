import toml
import os
import sys
import joblib
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
    crs_ids_path     = settings['crs_ids_path']
    models_path      = settings['models_path']
    figures_path     = settings['figures_path']
    dataset_path     = settings['dataset_path']
    paranoia_levels  = settings['params']['paranoia_levels']
    models           = settings['params']['models']

    # LOAD DATASET
    print('[INFO] Loading dataset...')
    
    loader = DataLoader(
        malicious_path  = os.path.join(dataset_path, 'malicious_train.json'),
        legitimate_path = os.path.join(dataset_path, 'legitimate_train.json')
    )    
    training_data = loader.load_data()

    models_weights = dict()
    
    for pl in paranoia_levels:
        # FEATURE EXTRACTION 
        print('[INFO] Extracting features for PL {}...'.format(pl))
        
        extractor = ModSecurityFeaturesExtractor(
            crs_ids_path = crs_ids_path,
            crs_path     = crs_dir,
            crs_pl       = pl
        )
    
        xtr, ytr = extractor.extract_features(training_data)

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

                # Save model
                joblib.dump(model, os.path.join(models_path, 'svc_{}.joblib'.format(pl)))

                models_weights['svc'][pl] = model.coef_
                
            elif model_name == 'rf':
                model = RandomForestClassifier(
                    class_weight = 'balanced',
                    random_state = 77,
                    n_jobs       = -1
                )
                model.fit(xtr, ytr)

                # Save model
                joblib.dump(model, os.path.join(models_path, 'rf_{}.joblib'.format(pl)))
