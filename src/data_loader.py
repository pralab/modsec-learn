import pandas as pd
import json


class DataLoader:
    """
    A class to load the dataset from the file system.
    """
    def __init__(self, malicious_path, legitimate_path):
        """
        Constructor of DataLoader class.

        Parameters:
        ----------
            malicious_path: str
                The path to the malicious dataset.
            legitimate_path: str
                The path to the benign dataset.
        
        Returns:
        --------
            self: object
        """
        self._malicious_path  = malicious_path
        self._legitimate_path = legitimate_path

    
    def load_data(self):
        """
        Load the dataset from the filesystem.

        Returns:
        --------
            pd.DataFrame
                The loaded dataset.
        """
        
        with open(self._legitimate_path, 'r') as file:
            legitimate_data= json.load(file)
        
        with open(self._malicious_path, 'r') as file:
            malicious_data = json.load(file)

        malicious_labels  = [1] * len(malicious_data)
        legitimate_labels = [0] * len(legitimate_data)
        combined_data     = malicious_data   + legitimate_data
        combined_labels   = malicious_labels + legitimate_labels

        return pd.DataFrame({
            'payload': combined_data,
            'label': combined_labels
        })