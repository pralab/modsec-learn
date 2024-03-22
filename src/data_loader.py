"""
A class to load the dataset from the filesystem.
"""

import pandas as pd


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
        legitimate_data = []
        with open(self._legitimate_path, 'r') as file:
            for line in file:
                legitimate_data.append(line.strip())
        
        malicious_data = []
        with open(self._malicious_path, 'r') as file:
            for line in file:            
                malicious_data.append(line.strip())

        malicious_labels  = [1] * len(malicious_data)
        legitimate_labels = [0] * len(legitimate_data)
        combined_data     = malicious_data   + legitimate_data
        combined_labels   = malicious_labels + legitimate_labels

        return pd.DataFrame({
            'payloads': combined_data,
            'labels': combined_labels
        })