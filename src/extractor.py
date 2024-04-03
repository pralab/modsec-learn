import numpy as np
import json
import os

from src.utils import type_check
from src.models import PyModSecurity


class ModSecurityFeaturesExtractor:
    """
    A class to extract features using ModSecurity WAF.
    """

    def __init__(
            self,
            crs_ids_path,
            crs_path,
            crs_threshold = 5.0,
            crs_pl        = 4,
            features_path = None,
            debug         = False
        ):
        """
        Constructor of ModSecurityFeaturesExtractor class.
        
        Parameters:
        ----------
            crs_ids_path: str
                The path to the JSON file containing the CRS IDs.
            crs_path: str
                The path to the ModSecurity CRS file.
            crs_threshold: float
                The threshold for ModSecurity WAF.
            crs_pl: int
                The paranoia level for ModSecurity WAF.
            features_path: str
                The path to the file to save the features.
            debug: bool
                Debug mode
                
        Returns:
        --------
            self: object
        """
        type_check(crs_path, str, "crs_path")
        type_check(crs_threshold, float, "crs_threshold")
        type_check(crs_pl, int, "crs_pl")
        
        # Load CRS rules IDs from a file if provided
        if crs_ids_path is not None:
            self._load_crs_rules_ids(crs_ids_path)
        else:
            self._crs_ids = list() 

        self._crs_ids_path = crs_ids_path
        self._pymodsec     = PyModSecurity(
            crs_path,
            crs_threshold,
            crs_pl
        )
        self._features_path      = features_path
        self._debug              = debug


    def extract_features(self, data):
        """
        Returns the features vector for the provided dataset.
        
        Parameters:
        ----------
            data: array-like of shape (n_samples,)
                The input samples to predict.
        
        Returns:
        --------
            X: np.ndarray 
                Features vector based on OWASP CRS rules with 
                shape (n_samples, n_features)
            y: np.ndarray
                The class labels for the samples.
        """
        if len(self._crs_ids) == 0:
            raise ValueError(
                "No CRS rules found, perform the extraction of CRS rules IDs \
                or load them from a file."
            )

        num_rules = len(self._crs_ids)
        X         = np.zeros((data.shape[0], num_rules))
        y         = data['labels']

        for idx, payload in enumerate(data['payloads']):  
            self._pymodsec._process_query(payload)
        
            for rule in self._pymodsec._get_triggered_rules():
                X[idx, self._crs_ids.index(rule)] = 1.0

        if self._features_path is not None:
            self._save_features(X, self._features_path)

        return X, np.array(y)


    def extract_crs_ids(self, data):
        """
        Extract the unique CRS rules IDs for the provided dataset. 
        If the `crs_ids_path` is provided, the CRS IDs will be saved
        into the filesystem.

        Parameters:
        ----------
            data: pandas DataFrame
                The dataset to extract the unique CRS rules IDs from.
        """    
        payloads = data.drop('labels', axis=1)['payloads']

        new_crs_ids = set()
        for payload in payloads:
            self._pymodsec._process_query(payload)
            triggered_rules = self._pymodsec._get_triggered_rules()
            new_crs_ids.update(triggered_rules)

        # Merge the new CRS rules IDs with the existing ones
        self._crs_ids = list(new_crs_ids.union(set(self._crs_ids)))

        if self._debug:
            print(f"[DEBUG] All unique triggered rules: {self._crs_ids}")

        if self._crs_ids_path is not None:
            self._save_crs_rules_ids()


    def _save_features(self, X, features_path):
        """
        Save the features into a binary file.

        Parameters:
        ----------
            X: np.ndarray
                The features vector.
            features_path: str
                The path to the file to save the features.
        """
        np.save(features_path, X, allow_pickle=True)


    def _save_crs_rules_ids(self):
        """
        Save the CRS rules IDs into a JSON file.
        """
        
        data = {"rules_ids": self._crs_ids}
        
        with open(self._crs_ids_path, 'w') as file:
            json.dump(data, file, indent=4)


    def _load_crs_rules_ids(self, path):
        """
        Load the CRS rules IDs from a JSON file.

        Parameters:
        ----------
            crs_path: str
                The path to the JSON file containing the CRS rules IDs.
        """
        if os.path.exists(path):
            with open(path, 'r') as file:
                self._crs_ids = json.load(file)['rules_ids']
        else:
            self._crs_ids = list()