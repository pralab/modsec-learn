import numpy as np

from sklearn.metrics import roc_curve, roc_auc_score, auc


def update_roc(fpr, tpr):
    """
    Update ROC values (FPR, TPR) when matplotlib fails to interpolate 
    them (only for ModSecurity PL1)
    
    Parameters
    ----------
    fpr: list
        False Positive Rate values.
    tpr: list
        True Positive Rate values.

    Returns
    -------
    fpr_values: np.array
        The updated False Positive Rate values.
    
    tpr_values: np.array
        The updated True Positive Rate values.
    """
    highest_tpr = 0.
    start_idx   = 0
        
    for fpr_i, tpr_i in zip(fpr, tpr):
        if fpr_i <= 0:
            start_idx += 1
            highest_tpr = tpr_i
        else:
            break
    
    fpr_values = [1e-6]
    tpr_values = [highest_tpr]
    
    for idx in range(start_idx, len(fpr)):
        fpr_values.extend([fpr[idx], fpr[idx]])
        tpr_values.extend([tpr[idx-1], tpr[idx]])

    return np.array(fpr_values), np.array(tpr_values)


def plot_roc(
    y_true, 
    y_scores,
    label_legend, 
    ax,
    plot_rand_guessing = True,
    log_scale          = False,
    legend_settings    = None,
    update_roc_values  = False
):   
    """
    Plot the ROC curve for a given model.

    Parameters
    ----------
    y_true: np.array
        True labels.
    y_scores: np.array
        Predicted scores.
    label_legend: str
        Label for the legend.
    ax: matplotlib.axes.Axes
        Axes object to plot the ROC curve.
    plot_rand_guessing: bool
        Whether to plot the random guessing line.
    log_scale: bool
        Whether to plot the x-axis in log scale.
    legend_settings: dict
        Dictionary with the legend settings.
    update_roc_values: bool
        Whether to update the ROC values, only for ModSecurity PL1.
    """ 
    auc = roc_auc_score(y_true, y_scores)
    fpr, tpr, _ = roc_curve(y_true, y_scores)
    
    # Update ROC values (FPR, TPR) when matplotlib fails to interpolate 
    # them (only for ModSecurity PL1)
    if update_roc_values:
        fpr, tpr = update_roc(fpr, tpr)
    
    if log_scale:
        ax.set_xscale('log')
    else:
        ax.set_xlim([-0.05, 1.05])

    ax.plot(fpr, tpr, label=label_legend + f' (AUC = {auc:.3f})')
    ax.set_ylim([-0.05, 1.05])
    ax.set_xlabel("False Positive Rate (FPR)", fontsize=14)
    ax.set_ylabel("True Positive Rate (TPR)", fontsize=14)
    ax.grid(True)
    ax.legend(**legend_settings)

    if plot_rand_guessing:
        ax.plot([0, 1], [0, 1], color="navy", lw=2, linestyle="--")