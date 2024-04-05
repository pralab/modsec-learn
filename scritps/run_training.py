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

import seaborn
import seaborn.objects as so
import numpy as np

def analyze_rules_importance(rules_selector=None, legend_fontsize=13, axis_labels_size=16, tick_labels_size=14):
    # setup paths
    crs_rules_dir                = config['crs_rules_dir']
    owasp_crs_rules_ids_filepath = config['crs_rules_ids']
    models_base_path             = config['models_path']
    pl                           = config['pl_advtrain']
    adv_examples_base_path       = config['adv_examples_base_path']
    data_path                    = config['data_path']
    figs_save_path               = config['figs_save_path']

    # owasp_crs_rules_ids_filepath = "/wafamole_testing/owasp_crs_sqli_rules_ids.json"
    with open(owasp_crs_rules_ids_filepath, 'r') as fp:
        data = json.load(fp)
        owasp_crs_ids = data['rules_ids']

    info_rules               = [942011, 942012, 942013, 942014, 942015, 942016, 942017, 942018]
    crs_rules_ids_pl1_unique = [942100, 942140, 942160, 942170, 942190, 942220, 942230, 942240, 942250, 942270, 942280, 942290, 942320, 942350, 942360, 942500]
    crs_rules_ids_pl3_unique = [942251, 942490, 942420, 942431, 942460, 942101, 942511]
    crs_rules_ids_pl4_unique = [942421, 942432]
    crs_rules_ids_pl2_unique = list(set([int(rule) for rule in owasp_crs_ids]) - set(crs_rules_ids_pl1_unique + crs_rules_ids_pl3_unique + crs_rules_ids_pl4_unique + info_rules))

    crs_rules_ids_pl1 = crs_rules_ids_pl1_unique
    crs_rules_ids_pl2 = crs_rules_ids_pl1 + crs_rules_ids_pl2_unique
    crs_rules_ids_pl3 = crs_rules_ids_pl2 + crs_rules_ids_pl3_unique
    crs_rules_ids_pl4 = crs_rules_ids_pl3 + crs_rules_ids_pl4_unique

    num_samples    = 2000
    warn_rules     = [942110, 942430, 942420, 942431, 942460, 942421, 942432]
    critical_rules = [rule for rule in crs_rules_ids_pl4 if rule not in warn_rules]


    benign_load_path = os.path.join(data_path, 'benign_samples_test_2000.pkl')
    with open(benign_load_path, 'rb') as fp:
        benign_samples = pickle.load(fp)
    assert isinstance(benign_samples, list) and len(benign_samples) == num_samples

    attacks_load_path = os.path.join(data_path, 'attack_samples_test_2000.pkl')
    with open(attacks_load_path, 'rb') as fp:
        attack_samples = pickle.load(fp)
    assert isinstance(attack_samples, list) and len(attack_samples) == num_samples
    
    assert 0 < pl < 5

    adv_payloads_filename =  os.path.join(adv_examples_base_path, 'output_svm_linear_pl{pl}_2000samples_rs20_100rounds.json'.format(pl=pl))
    model_savename = 'linear_svc_pl{}.joblib'.format(pl)
    model_advtrain_savename = 'linear_svc_pl{}_adv.joblib'.format(pl)

    if pl == 1:
        rules_filter = crs_rules_ids_pl1
    elif pl == 2:
        rules_filter = crs_rules_ids_pl2
    elif pl == 3:
        rules_filter = crs_rules_ids_pl3
    elif pl == 4:
        rules_filter = crs_rules_ids_pl4

    ##
    # End setup
    ##

    pyms = PyModSecurity(crs_rules_dir, pl, owasp_crs_ids)
    benign_data, benign_scores = pyms.process_payloads(benign_samples)
    attack_data, attack_scores = pyms.process_payloads(attack_samples)

    df_benign = pd.DataFrame(data=benign_data, index=list(range(num_samples)), columns=owasp_crs_ids)
    df_attack = pd.DataFrame(data=attack_data, index=list(range(num_samples)), columns=owasp_crs_ids)

    X_test = np.vstack((attack_data, benign_data))
    assert X_test.shape[0] == attack_data.shape[0] + benign_data.shape[0]
    assert X_test.shape[1] == attack_data.shape[1] and X_test.shape[1] == benign_data.shape[1]
    # y_test = np.concatenate((np.ones(num_samples), np.zeros(num_samples)))
    # y_scores = np.concatenate((attack_scores, benign_scores))
    # df_test = pd.DataFrame(data=X_test, index=list(range(num_samples * 2)), columns=owasp_crs_ids)

    adv_payloads = []
    with open(adv_payloads_filename) as fp:
        idx = 0
        for result in fp.readlines():
            data = json.loads(result)
            adv_payloads.append(data['adv_payload'])

    adv_data, adv_scores = pyms.process_payloads(adv_payloads)
    assert attack_data.shape[0] == adv_data.shape[0] and len(attack_scores) == len(adv_scores)
    df_adv = pd.DataFrame(data=adv_data, index=list(range(num_samples)), columns=owasp_crs_ids)


# Da qua sembra interessante


    model = joblib.load(os.path.join(models_base_path, model_savename))
    model_advtrain = joblib.load(os.path.join(models_base_path, model_advtrain_savename))

    # rules to be removed from the plots: rules that are not triggered by any benign, attack and adv. samples
    rules_to_remove = []
    for rule in owasp_crs_ids:
        if df_attack[rule].sum() == 0 and df_benign[rule].sum() == 0 and df_adv[rule].sum():
            rules_to_remove.append(rule)
    # print("RULES NEVER TRIGGERED: {}".format(rules_to_remove))

    # select rules related to target PL, sort them alphabetically
    select_rules = sorted([rule for rule in owasp_crs_ids if (int(rule) in rules_filter) and (rule not in rules_to_remove)])

    delta = (df_adv[select_rules] - df_attack[select_rules]).mean().values
    assert delta.flatten().shape[0] == len(select_rules)

    rules_delta = {r: s for r, s in zip(select_rules, delta.tolist())}
    rules_delta = dict(sorted(rules_delta.items(), key=lambda item: item[1], reverse=False))  # reverse=True
    sorted_rules = list(rules_delta.keys())

    weights = model.calibrated_classifiers_[0].base_estimator.coef_.copy().flatten()
    weights_advtrain = model_advtrain.calibrated_classifiers_[0].base_estimator.coef_.copy().flatten()
    
    # sort weights according to the order of select_rules:
    weights = np.array([weights[owasp_crs_ids.index(rule)] for rule in sorted_rules])
    weights_advtrain = np.array([weights_advtrain[owasp_crs_ids.index(rule)] for rule in sorted_rules])
    assert tuple(weights.shape) == tuple(delta.shape) and tuple(weights_advtrain.shape) == tuple(delta.shape)

    # rules_importance = weights * delta

    # df_results = pd.DataFrame(
    #     data={
    #         'Rule': sorted_rules,
    #         'Imp': rules_importance.tolist(),
    #         'Weight': weights.tolist(),
    #         'Prob': delta.tolist()
    #     }
    # )

    # df_results_sorted = df_results.sort_values(by='Imp', key=lambda col: np.abs(col), ascending=False)  # ascending=False
    weights = weights / np.linalg.norm(weights)
    weights_advtrain = weights_advtrain / np.linalg.norm(weights_advtrain)
    
    pos_rules, neg_rules, same_rules = [], [], []
    for rule, slope in rules_delta.items():
        if slope > 0:
            pos_rules.append(rule)
        elif slope < 0:
            neg_rules.append(rule)
        else:
            same_rules.append(rule)
    
    if rules_selector is not None and isinstance(rules_selector, list):
        weights = np.array([w for w, rule in zip(weights.tolist(), sorted_rules) if rule if rule[3:] in rules_selector])
        weights_advtrain = np.array([w for w, rule in zip(weights_advtrain.tolist(), sorted_rules) if rule if rule[3:] in rules_selector])
        sorted_rules = [rule for rule in sorted_rules if rule[3:] in rules_selector]
        weights_filename = 'weights_comparison_svm_new.pdf'
        rules_activation_filename = 'comparison_attack_adv_svm_new.pdf'
    else:
        weights_filename = 'weights_comparison_svm.pdf'
        rules_activation_filename = 'comparison_attack_adv_svm.pdf'

    adv_prob = df_adv[sorted_rules].mean().values.tolist()
    attack_prob = df_attack[sorted_rules].mean().values.tolist() 

    df_plot = pd.DataFrame(
        {
            'rules': sorted_rules * 2,
            'prob': adv_prob + attack_prob,
            'type': (['adversarial'] * len(sorted_rules)) + (['malicious'] * len(sorted_rules))
        }
    )

    fig_prob, ax_prob = plt.subplots(1, 1)
    p = so.Plot(
        df_plot, 
        x='rules', 
        y='prob', 
        color='type'
    ) \
        .add(so.Bar(), legend=True)\
        .scale(color=['orange', 'deepskyblue'])\
        .on(ax_prob)\
        .plot()
    
    ax_prob.set_xticklabels([rule[3:] for rule in sorted_rules], rotation=75, ha='right', rotation_mode='anchor')
    legend = fig_prob.legends.pop(0)
    ax_prob.legend(legend.legendHandles, [t.get_text() for t in legend.texts], loc='upper right', fancybox=True, shadow=False, fontsize=legend_fontsize)
    ax_prob.set_xlabel('CRS SQLi Rules', fontsize=axis_labels_size, labelpad=10)
    ax_prob.set_ylabel('Activation probability', fontsize=axis_labels_size, labelpad=10)
    ax_prob.set_xmargin(0.05)
    ax_prob.set_ymargin(0.05)
    ax_prob.xaxis.set_tick_params(labelsize=tick_labels_size)
    ax_prob.yaxis.set_tick_params(labelsize=tick_labels_size)
    ax_prob.grid(visible=True, axis='both', color='gray', linestyle='dotted')
    fig_prob.set_size_inches(16, 6)
    fig_prob.tight_layout()
    fig_prob.savefig(os.path.join(figs_save_path, rules_activation_filename), dpi=600, format='pdf', bbox_inches="tight")





    fig_weights_cmp, ax_weights_cmp = plt.subplots(1, 1)
    x_values = np.arange(len(sorted_rules))
        
    # Bar plot using seaborn
    df_plot = pd.DataFrame(
        {
            'rules': sorted_rules * 2,
            'weight': weights_advtrain.tolist() + weights.tolist(),
            'type': (['AdvModSec (SVM)'] * len(sorted_rules)) + (['MLModSec (SVM)'] * len(sorted_rules))
        }
    )
    p = so.Plot(
        df_plot, 
        x='rules', 
        y='weight', 
        color='type'
    )\
        .add(so.Bar())\
        .scale(color=['orange', 'deepskyblue'])\
        .on(ax_weights_cmp)\
        .plot()
    
    ax_weights_cmp.set_xticklabels(
        [rule[3:] for rule in sorted_rules],
        rotation=75,
        ha='right',
        rotation_mode='anchor'
    )
    
    legend = fig_weights_cmp.legends.pop(0)
    ax_weights_cmp.legend(
        legend.legendHandles, 
        [t.get_text() for t in legend.texts], 
        loc='upper right', 
        fancybox=True,
        shadow=False,
        fontsize=legend_fontsize
    )
    
    ax_weights_cmp.set_xlabel('CRS SQLi Rules', fontsize=axis_labels_size, labelpad=10)
    ax_weights_cmp.set_ylabel('Weight', fontsize=axis_labels_size, labelpad=10)
    ax_weights_cmp.set_xmargin(0.05)
    ax_weights_cmp.set_ymargin(0.05)
    ax_weights_cmp.xaxis.set_tick_params(labelsize=tick_labels_size)
    ax_weights_cmp.yaxis.set_tick_params(labelsize=tick_labels_size)
    ax_weights_cmp.grid(visible=True, axis='both', color='gray', linestyle='dotted')
    fig_weights_cmp.set_size_inches(16, 6)
    fig_weights_cmp.tight_layout()
    fig_weights_cmp.savefig(os.path.join(figs_save_path, weights_filename), dpi=600, format='pdf', bbox_inches="tight")





















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
                joblib.dump(model, os.path.join(models_path, 'linear_svc_pl{}.joblib'.format(pl)))

                #models_weights['svc'][pl] = model.coef_
                
            elif model_name == 'rf':
                model = RandomForestClassifier(
                    class_weight = 'balanced',
                    random_state = 77,
                    n_jobs       = -1
                )
                model.fit(xtr, ytr)

                # Save model
                joblib.dump(model, os.path.join(models_path, 'rf_pl{}.joblib'.format(pl)))
