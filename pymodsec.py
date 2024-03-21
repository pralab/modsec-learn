import os
import numpy as np

from utils import type_check
from urllib.parse import quote_plus
from rules_logger import RulesLogger
from ModSecurity import ModSecurity, RulesSet, Transaction, LogProperty


class PyModSecurity():
    """PyModSecurity WAF wrapper"""

    _BAD_STATUS_CODES = [401, 403]
    _GOOD_STATUS_CODES = list(range(200, 209))
    _SELECTED_RULES_FILES = [
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        "REQUEST-949-BLOCKING-EVALUATION.conf"
    ]

    def __init__(
            self,
            rules_dir: str,
            threshold=5.0,
            pl=1,
            output_type='binary'
        ):
        """
        Constructor of PyModsecurity class
        
        Arguments
        ---------
            rules_dir: str
                Path to the directory containing the CRS rules.
            threshold: float
                The threshold to use for the ModSecurity CRS.
            pl: int from 1 to 4
                The paranoia level to use for the ModSecurity CRS.
            output_type: str
                The output type of the WAF. Can be 'binary' or 'score'.
        """
        type_check(rules_dir, str, 'rules_dir')
        type_check(threshold, float, 'threshold')
        type_check(pl, int, 'pl'),
        type_check(output_type, str, 'output_type')
        
        self._modsec                = ModSecurity()
        self._rules                 = RulesSet()
        self._rules_logger_callback = None
        self._threshold             = threshold
        
        base_path        = os.path.abspath(rules_dir)
        config_rule_file = "./modsec_config/REQUEST-901-INITIALIZATION_PL{pl}_THR{thr}.conf"

        # Load inizialization rules
        self._rules.loadFromUri(
            config_rule_file.format(pl=pl, thr=int(threshold))
        )
        
        # Load the WAF rules
        try:
            for file_name in PyModSecurity._SELECTED_RULES_FILES:
                self._rules.loadFromUri(os.path.join(base_path, file_name))
        except OSError as error:
            raise SystemExit(
                "Error loading the rules for PyModsecurity: {}".format(error)
            )
        
        # Check for parsing errors
        error_str = self._rules.getParserError()
        if error_str != '':
            raise SystemExit(
                "Error parsing the rules: {}".format(error_str)
            )
        
        if output_type not in ['binary', 'score']:
            raise ValueError(
                "Invalid value for mode input param: {}. Valid values are: ['binary', 'score']"
                    .format(output_type)
            )
        self._output_type = output_type

        print("[INFO] Using ModSecurity CRS with PL = {} and INBOUND THRESHOLD = {}"
                .format(pl, threshold)
        )


    def process_query(self, payload: str):
        """
        Process the provided payload using the ModSecurity CRS WAF.

        Arguments:
        ----------
            payload: str
                The payload to process. 
        """
        # Setting the callback for the rules logger
        rules_logger_cb = RulesLogger(threshold=self._threshold)
        self._modsec.setServerLogCb2(
            rules_logger_cb, 
            LogProperty.RuleMessageLogProperty
        )
        self._rules_logger_cb = rules_logger_cb

        # Remove encoding from the payload
        payload = quote_plus(payload)

        # Process the payload using the ModSecurity CRS
        transaction = Transaction(self._modsec, self._rules)
        transaction.processURI(
            "http://127.0.0.1:80?{}".format(payload), 
            "GET", 
            "HTTP/1.1"
        )
        transaction.processRequestHeaders()
        transaction.processRequestBody()

    
    def _process_response(self) -> float:
        """
        Processes the HTTP response received from the ModSecurity CRS

        Returns:
        --------
            score: float
                The score of the response if the output type is 'score', 0.0 if the
                output type is 'binary' and the response is good, 1.0 if the response
                is bad.
        """
        if self._rules_logger_cb is not None:
            if self._output_type == 'binary':
                if self._rules_logger_cb.get_status() in __class__._BAD_STATUS_CODES:
                    return 1.0
                else:
                    return 0.0
            elif self._output_type == 'score':
                return self._rules_logger_cb.get_score()
        else:
            raise SystemExit("Callback to process rules not initialized")


    def predict(self, X):
        """
        Predict the class labels for samples in X, if the output type is 'binary', 
        however if the output type is 'score', it returns the score of samples in X.

        Arguments:
        ----------
            X: array-like of shape (n_samples,)
                The input samples to predict.

        Returns
        -------
            y_pred : ndarray of shape (n_samples,)
                Vector containing the class labels/score for each sample.
        """
        def process_and_get_prediction(x):
            self.process_query(x)
            return self._process_response()

        if len(X.shape) == 1:
            scores = np.array(
                list(map(process_and_get_prediction, X))
            )
        else:
            raise ValueError(
                "Invalid input shape. Expected 1D array, got {}D array"
                    .format(len(X.shape))
            )
        
        return scores

    def get_triggered_rules(self):
        """
        Returns the list of the triggered rules.

        Returns:
        --------
            list
                The list of the triggered rules.
        """
        return self._rules_logger_cb.get_rules()