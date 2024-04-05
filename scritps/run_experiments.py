import os
import matplotlib.pyplot as plt
import toml
import sys
import joblib
import numpy as np
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.models import PyModSecurity
from src.data_loader import DataLoader
from src.extractor import ModSecurityFeaturesExtractor
from src.utils.plotting import plot_roc
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression,ElasticNet, Lasso


if  __name__ == '__main__':
    settings         = toml.load('config.toml')
    crs_dir          = settings['crs_dir']
    crs_ids_path     = settings['crs_ids_path']
    models_path      = settings['models_path']
    figures_path     = settings['figures_path']
    dataset_path     = settings['dataset_path']
    paranoia_levels  = settings['params']['paranoia_levels']
    linear_models    = settings['params']['linear_models']
    models           = settings['params']['models']
    penalties        = settings['params']['penalties']
    fig, axs         = plt.subplots(2, 2)
    zoom_axs         = dict()
    
    # LOAD DATASET
    print('[INFO] Loading dataset...')

    legitimate_train_path = os.path.join(dataset_path, 'legitimate_train.json')
    malicious_train_path  = os.path.join(dataset_path, 'malicious_train.json')
    legitimate_test_path  = os.path.join(dataset_path, 'legitimate_test.json')
    malicious_test_path   = os.path.join(dataset_path, 'malicious_test.json')

    loader = DataLoader(
        malicious_path  = malicious_train_path,
        legitimate_path = legitimate_train_path
    )    
    training_data = loader.load_data()

    loader = DataLoader(
        malicious_path  = malicious_test_path,
        legitimate_path = legitimate_test_path
    )    
    test_data = loader.load_data()
    
    # FEATURE EXTRACTION / TRAINING / PREDICTION
    for pl in paranoia_levels:
        print('[INFO] Extracting features for PL {}...'.format(pl))
        
        extractor = ModSecurityFeaturesExtractor(
            crs_ids_path = crs_ids_path,
            crs_path     = crs_dir,
            crs_pl       = pl
        )
    
        xts, yts = extractor.extract_features(test_data)

        for model_name in models:
            print('[INFO] Evaluating {} model for PL {}...'.format(model_name, pl))
                        
            if model_name == 'rf':
                model       = joblib.load(os.path.join(models_path, 'rf_pl{}.joblib'.format(pl)))
                y_preds     = model.predict(xts)
                y_scores    = model.predict_proba(xts)[:, 1]
                
            elif model_name == 'modsec':
                waf = PyModSecurity(
                    rules_dir = crs_dir,
                    pl        = pl
                )
                y_scores = waf.predict(test_data['payloads'])
            

            plot_roc(
                yts, 
                y_scores, 
                label_legend       = model_name.upper(),
                ax                 = axs.flatten()[pl-1],
                plot_rand_guessing = False,
                log_scale          = True,
                legend_settings    = {'loc': 'lower left', 'fontsize': 'small'},
                update_roc_values  = True if pl == 1 else False,
                include_zoom       = True,
                zoom_axs           = zoom_axs,
                pl                 = pl
            )

        for model_name in linear_models:
            print('[INFO] Evaluating {} model for PL {}...'.format(model_name, pl))

            for penalty in penalties:
                if model_name == 'svc':
                    model = joblib.load(os.path.join(models_path, 'linear_svc_pl{}_{}.joblib'.format(pl, penalty)))
                    y_preds  = model.predict(xts)
                    y_scores = model.decision_function(xts)
                    

                elif model_name == 'log_reg':
                    model = joblib.load(os.path.join(models_path, 'log_reg_pl{}_{}.joblib'.format(pl, penalty)))
                    y_preds  = model.predict(xts)
                    y_scores = model.predict_proba(xts)[:, 1]
                    

                plot_roc(
                    yts, 
                    y_scores, 
                    label_legend       = f'{model_name.upper()} - {penalty.upper()}',
                    ax                 = axs.flatten()[pl-1],
                    plot_rand_guessing = False,
                    log_scale          = True,
                    legend_settings    = {'loc': 'lower left', 'fontsize': 'small'},
                    update_roc_values  = True if pl == 1 else False,
                    include_zoom       = True,
                    zoom_axs           = zoom_axs,
                    pl                 = pl
                )

    # Final settings for the plot
    for idx, ax in enumerate(axs.flatten()):
        ax.set_title('PL {}'.format(idx+1), fontsize=16)
        ax.xaxis.label.set_size(16)
        ax.yaxis.label.set_size(16)
        
    fig.set_size_inches(15, 15)
    fig.tight_layout(pad=2.0)
    fig.savefig(
        os.path.join(figures_path, 'roc_curves_zoom1.pdf'),
        dpi         = 600,
        format      = 'pdf',
        bbox_inches = "tight"
    )