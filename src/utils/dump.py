import pickle
import joblib


def save_scores_and_labels(y_scores_model1, y_scores_model2, y_ts, waf_scores, file_name=None):
    
    data_to_save = {
        'y_scores': y_scores_model1,
        'y_scores_rf': y_scores_model2,  
        'y_ts': y_ts,          
        'waf_scores': waf_scores  
    }
    with open(file_name, 'wb') as file:
        pickle.dump(data_to_save, file)
    
    print(f"Data successfully saved to {file_name}.")


def load_scores_and_labels(file_name=None):
    
    with open(file_name, 'rb') as file:
    
        data_loaded = pickle.load(file)
    
    print(f"Data successfully loaded from {file_name}.")
    
    return data_loaded    



