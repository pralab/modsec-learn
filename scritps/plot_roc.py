from sklearn.metrics import roc_curve, roc_auc_score, auc
import matplotlib.pyplot as plt
from src.save_load_data import load_scores_and_labels



##############
# Load the data
##############
data_loaded_pl1 = load_scores_and_labels('scores_and_labels_pl_1.pkl')
data_loaded_pl2 = load_scores_and_labels('scores_and_labels_pl_2.pkl')
data_loaded_pl3 = load_scores_and_labels('scores_and_labels_pl_3.pkl')
data_loaded_pl4 = load_scores_and_labels('scores_and_labels_pl_4.pkl')

y_scores_svc_pl1 = data_loaded_pl1['y_scores']  
y_scores_rf_pl1 = data_loaded_pl1['y_scores_rf']
y_ts_pl1 = data_loaded_pl1['y_ts']          
waf_scores_pl1 = data_loaded_pl1['waf_scores']  

y_scores_svc_pl2 = data_loaded_pl2['y_scores']  
y_scores_rf_pl2 = data_loaded_pl2['y_scores_rf']
y_ts_pl2 = data_loaded_pl2['y_ts']
waf_scores_pl2 = data_loaded_pl2['waf_scores']

y_scores_svc_pl3 = data_loaded_pl3['y_scores']
y_scores_rf_pl3 = data_loaded_pl3['y_scores_rf']
y_ts_pl3 = data_loaded_pl3['y_ts']
waf_scores_pl3 = data_loaded_pl3['waf_scores']

y_scores_svc_pl4 = data_loaded_pl4['y_scores']
y_scores_rf_pl4 = data_loaded_pl4['y_scores_rf']
y_ts_pl4 = data_loaded_pl4['y_ts']
waf_scores_pl4 = data_loaded_pl4['waf_scores']



aucsvc_pl1 = roc_auc_score(y_ts_pl1, y_scores_svc_pl1)
aucmod_pl1 = roc_auc_score(y_ts_pl1, waf_scores_pl1)
aucrf_pl1 = roc_auc_score(y_ts_pl1, y_scores_rf_pl1)
fprsvc_pl1, tprsvc_pl1, _ = roc_curve(y_ts_pl1, y_scores_svc_pl1)
fprrf_pl1, tprrf_pl1, _ = roc_curve(y_ts_pl1, y_scores_rf_pl1)
fprmod_pl1, tprmod_pl1, _ = roc_curve(y_ts_pl1, waf_scores_pl1)

aucsvc_pl2 = roc_auc_score(y_ts_pl2, y_scores_svc_pl2)
aucmod_pl2 = roc_auc_score(y_ts_pl2, waf_scores_pl2)    
aucrf_pl2 = roc_auc_score(y_ts_pl2, y_scores_rf_pl2)
fprsvc_pl2, tprsvc_pl2, _ = roc_curve(y_ts_pl2, y_scores_svc_pl2)   
fprrf_pl2, tprrf2, _ = roc_curve(y_ts_pl2, y_scores_rf_pl2)
fprmod_pl2, tprmod_pl2, _ = roc_curve(y_ts_pl2, waf_scores_pl2)

aucsvc_pl3 = roc_auc_score(y_ts_pl3, y_scores_svc_pl3)
aucmod_pl3 = roc_auc_score(y_ts_pl3, waf_scores_pl3)
aucrf_pl3 = roc_auc_score(y_ts_pl3, y_scores_rf_pl3)
fprsvc_pl3, tprsvc_pl3, _ = roc_curve(y_ts_pl3, y_scores_svc_pl3)
fprrf_pl3, tprrf3, _ = roc_curve(y_ts_pl3, y_scores_rf_pl3)
fprmod_pl3, tprmod_pl3, _ = roc_curve(y_ts_pl3, waf_scores_pl3)

aucsvc_pl4 = roc_auc_score(y_ts_pl4, y_scores_svc_pl4)
aucmod_pl4 = roc_auc_score(y_ts_pl4, waf_scores_pl4)
aucrf_pl4 = roc_auc_score(y_ts_pl4, y_scores_rf_pl4)
fprsvc_pl4, tprsvc_pl4, _ = roc_curve(y_ts_pl4, y_scores_svc_pl4)
fprrf_pl4, tprrf4, _ = roc_curve(y_ts_pl4, y_scores_rf_pl4)
fprmod_pl4, tprmod_pl4, _ = roc_curve(y_ts_pl4, waf_scores_pl4)

fig, axs = plt.subplots(2, 2, figsize=(12, 10))
axs[0,0].plot(fprsvc_pl1, tprsvc_pl1, label=f'SVM (AUC = {aucsvc_pl1:.3f})')
axs[0,0].plot(fprrf_pl1, tprrf_pl1, label=f'Random Forest (AUC = {aucrf_pl1:.3f})')
axs[0,0].plot(fprmod_pl1, tprmod_pl1, label=f'ModSecurity (AUC = {aucmod_pl1:.3f})')
axs[0,0].set_xscale('log')
axs[0,0].set_ylim([-0.05, 1.05])
axs[0,0].set_xlabel("False Positive Rate (FPR)", fontsize=14)
axs[0,0].set_ylabel("True Positive Rate (TPR)", fontsize=14)
axs[0,0].set_title("ROC Curve pl 1")
axs[0,0].legend()   
axs[0,0].grid()

axs[0,1].plot(fprsvc_pl2, tprsvc_pl2, label=f'SVM (AUC = {aucsvc_pl2:.3f})')
axs[0,1].plot(fprmod_pl2, tprmod_pl2, label=f'ModSecurity (AUC = {aucmod_pl2:.3f})')
axs[0,1].plot(fprrf_pl2, tprrf2, label=f'Random Forest (AUC = {aucrf_pl2:.3f})')
axs[0,1].set_xscale('log')
axs[0,1].set_ylim([-0.05, 1.05])
axs[0,1].set_xlabel("False Positive Rate (FPR)", fontsize=14)
axs[0,1].set_title("ROC Curve pl 2")
axs[0,1].legend()   
axs[0,1].grid()

axs[1,0].plot(fprsvc_pl3, tprsvc_pl3, label=f'SVM (AUC = {aucsvc_pl3:.3f})')
axs[1,0].plot(fprmod_pl3, tprmod_pl3, label=f'ModSecurity (AUC = {aucmod_pl3:.3f})')
axs[1,0].plot(fprrf_pl3, tprrf3, label=f'Random Forest (AUC = {aucrf_pl3:.3f})')
axs[1,0].set_xscale('log')
axs[1,0].set_ylim([-0.05, 1.05])
axs[1,0].set_xlabel("False Positive Rate (FPR)", fontsize=14)
axs[1,0].set_ylabel("True Positive Rate (TPR)", fontsize=14)
axs[1,0].set_title("ROC Curve pl 3")
axs[1,0].legend()
axs[1,0].grid()

axs[1,1].plot(fprsvc_pl4, tprsvc_pl4, label=f'SVM (AUC = {aucsvc_pl4:.3f})')
axs[1,1].plot(fprmod_pl4, tprmod_pl4,  label=f'ModSecurity (AUC = {aucmod_pl4:.3f})')
axs[1,1].plot(fprrf_pl4, tprrf4, label=f'Random Forest (AUC = {aucrf_pl4:.3f})')
axs[1,1].set_xscale('log')
axs[1,1].set_ylim([-0.05, 1.05])
axs[1,1].set_xlabel("False Positive Rate (FPR)", fontsize=14)
axs[1,1].set_title("ROC Curve pl 4")
axs[1,1].legend()
axs[1,1].grid()


plt.tight_layout()
plt.savefig('roc_curve_comparison_all_pl.pdf')
plt.show()
