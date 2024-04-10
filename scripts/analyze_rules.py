"""
This script is used to create a graphical comparison of the weights assigned to the CRS rules 
by the ML models with L1 and L2 regularization and the ModSecurity WAF.
"""

import toml
import os
import sys
import joblib
import matplotlib.pyplot as plt
import seaborn.objects as so
import numpy as np
import pandas as pd
import json
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from sklearn.preprocessing import minmax_scale


def analyze_weights(
    model_name,
    model_l1,
    model_l2,
    crs_ids,
    crs_weights,
    figure_path,
    legend_fontsize  = 18,
    axis_labels_size = 20,
    tick_labels_size = 18
):
    """
    Analyze the assigned weights for the ML models with L1 and L2 regularization
    and ModSecurity WAF. The weights are compared for each CRS rule.

    Parameters
    ----------
    model_name: str
        The name of the model.
    model_l1: sklearn.linear_model
        The model with L1 regularization.
    model_l2: sklearn.linear_model
        The model with L2 regularization.
    crs_ids: list
        A list with the CRS IDs.
    crs_weights: dict
        A dictionary with the weights of the CRS rules.
    figure_path: str
        The path to save the figure.
    legend_fontsize: int
        The font size of the legend.
    axis_labels_size: int
        The font size of the axis labels.
    tick_labels_size: int
        The font size of the tick labels.
    """
    # Extract the weights from the models
    model_l1_weights = model_l1.coef_.flatten()
    model_l2_weights = model_l2.coef_.flatten()

    modsec_weights = np.array([int(crs_weights[rule]) for rule in crs_ids])
    # Needed to scale correctly ModSec weights, it will not be used for the plot
    modsec_weights = np.append(modsec_weights, 0) 
    modsec_weights = minmax_scale(
        modsec_weights, 
        feature_range = (0, model_l1_weights.max())
    )

    fig, axs = plt.subplots(1, 1)
    
    # Create the DataFrame for the plot
    df_plot = pd.DataFrame(
        {
            'rules': crs_ids * 3,
            'weight': modsec_weights.tolist()[:-1] + 
                      model_l1_weights.tolist() + 
                      model_l2_weights.tolist(),
            'type': ['ModSec'] * len(crs_ids) + 
                    [f'{model_name} - $\ell_1$'] * len(crs_ids) + 
                    [f'{model_name} - $\ell_2$'] * len(crs_ids)
        }
    )

    _ = so.Plot(
        df_plot, 
        x     = 'rules',
        y     = 'weight',
        color = 'type'
    ) \
        .add(so.Bar()) \
        .scale(color=['#aedc41', '#81b8ef', '#fe6d73']) \
        .on(axs) \
        .plot()
    
    legend = fig.legends.pop(0)

    axs.set_xticklabels(
        [rule[3:] for rule in crs_ids], 
        rotation      = 75,
        ha            = 'right',
        rotation_mode = 'anchor'
    )
    axs.legend(
        legend.legendHandles, 
        [t.get_text() for t in legend.texts], 
        loc      = 'lower right',
        fancybox = True,
        shadow   = False,
        fontsize = legend_fontsize
    )
    
    axs.set_xlabel('CRS SQLi Rules', fontsize=axis_labels_size, labelpad=10)
    axs.set_ylabel('Weight', fontsize=axis_labels_size, labelpad=10)
    axs.set_xmargin(0.05)
    axs.set_ymargin(0.15)
    axs.xaxis.set_tick_params(labelsize=tick_labels_size)
    axs.yaxis.set_tick_params(labelsize=tick_labels_size)
    
    axs.grid(visible=True, axis='both', color='gray', linestyle='dotted')
    
    fig.set_size_inches(18, 8)
    fig.tight_layout()
    fig.savefig(
        os.path.join( 
            figure_path,
            '{}_weights_comp.pdf'.format(model_name.lower())
        ), 
        dpi         = 600,
        format      = 'pdf',
        bbox_inches = "tight"
    )


if __name__ == '__main__':
    settings         = toml.load('config.toml')
    crs_ids_path     = settings['crs_ids_path']
    crs_weiths_path  = settings['crs_weights_path']
    models_path      = settings['models_path']
    figures_path     = settings['figures_path']
    pl               = 4

    with open(crs_ids_path) as file:
        crs_ids = sorted(json.load(file)['rules_ids'])
    
    with open(crs_weiths_path) as file:
        weights = json.load(file)['weights']
    
    # Linear SVC
    model_name = 'linear_svc_pl{}_l1.joblib'.format(pl)
    model_l1      = joblib.load(
        os.path.join(models_path, model_name)
    )
    model_name = 'linear_svc_pl{}_l2.joblib'.format(pl)
    model_l2      = joblib.load(
        os.path.join(models_path, model_name)
    )

    analyze_weights(
        'SVM',
        model_l1,
        model_l2,
        crs_ids,
        weights,
        figures_path
    )

    # Logistic Regression
    model_name = 'log_reg_pl{}_l1.joblib'.format(pl)
    model_l1      = joblib.load(
        os.path.join(models_path, model_name)
    )
    model_name = 'log_reg_pl{}_l2.joblib'.format(pl)
    model_l2      = joblib.load(
        os.path.join(models_path, model_name)
    )

    analyze_weights(
        'LR',
        model_l1,
        model_l2,
        crs_ids,
        weights,
        figures_path
    )