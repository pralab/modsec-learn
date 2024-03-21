import numpy as np

from utils import type_check
from pymodsec import PyModSecurity


class ModSecurityFeaturesExtractor:
    """
    A class to extract features from a given payload using ModSecurity WAF.
    """

    def __init__(self, crs_rules_ids, rules_base_path, crs_threshold, crs_pl):
        type_check(crs_rules_ids, list, "crs_rules_ids")
        type_check(crs_threshold, float, "crs_threshold")
        type_check(crs_pl, int, "crs_pl")
        
        self._crs_rules_ids = crs_rules_ids
        self._pymodsec = PyModSecurity(rules_base_path, crs_threshold, crs_pl)


    def extract_features(self, payload: str):
        """
        It returns the features vector for the provided payload.
        
        Arguments:
        ----------
            payload (str) : An payload to be analyzed
        
        Raises:
        -------
            TypeError: params has wrong types
        
        Returns:
        --------
            numpy ndarray : features vector based on OWASP CRS rules
        """
        type_check(payload, str, "payload")

        self._pymodsec.process_query(payload)
        
        triggered_rules = self._pymodsec.get_triggered_rules()
        
        # Remap each rule ID to a new numerical ID used as column index of the numpy 
        # array. This is needed because OWASP rule IDs range in [900,000 999,999] 
        # and each rule ID must be remapped to [0, N], where N is the length of 
        # self._crs_rules_ids list (which can be a sub-set of the whole OWASP CRS.
        # For example, if considering only OWASP CRS rules against SQL-i are 
        # that are defined in the  942,000 - 942,999 block, they are re-mapped 
        # to [0, 999]

        num_rules   = len(self._crs_rules_ids)
        features    = np.zeros((num_rules,))
        
        for rule in triggered_rules:
            features[self._crs_rules_ids.index(rule)] = 1.0

        return features