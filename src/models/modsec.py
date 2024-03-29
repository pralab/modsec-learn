"""
A wrapper for the ModSecurity CRS WAF.
"""

import os
import numpy as np
import re

from src.utils import type_check
from urllib.parse import quote_plus
from ModSecurity import ModSecurity, RulesSet, Transaction, LogProperty


class PyModSecurity():
    """PyModSecurity WAF wrapper"""

    _BAD_STATUS_CODES = [401, 403]
    _GOOD_STATUS_CODES = list(range(200, 209))
    _SELECTED_RULES_FILES = [
        'REQUEST-901-INITIALIZATION.conf',
        'REQUEST-942-APPLICATION-ATTACK-SQLI.conf'
    ]

    def __init__(
            self,
            rules_dir,
            threshold   = 5.0,
            pl          = 4,
            output_type = 'score',
            debug       = False
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

        # Check if the paranoia level is valid
        if not 1 <= pl <= 4:
            raise ValueError(
                "Invalid value for pl input param: {}. Valid values are: [1, 2, 3, 4]"
                    .format(pl)
            )
        
        # Check if the output type is valid
        if output_type not in ['binary', 'score']:
            raise ValueError(
                "Invalid value for mode input param: {}. Valid values are: ['binary', 'score']"
                    .format(output_type)
            )
        
        self._output_type           = output_type
        self._modsec                = ModSecurity()
        self._rules                 = RulesSet()
        self._rules_logger_callback = None
        self._threshold             = threshold
        self._debug                 = debug

        # Load the ModSecurity CRS configuration files
        for conf_file in ['modsecurity.conf', f'crs-setup-pl{pl}.conf']:
            config_path = os.path.join('./modsec_config', conf_file)
            assert os.path.isfile(config_path)
            self._rules.loadFromUri(config_path)
    
        # Load the WAF rules
        for filename in PyModSecurity._SELECTED_RULES_FILES:
            rule_path = os.path.join(os.path.abspath(rules_dir), filename)
            assert os.path.isfile(rule_path)
            self._rules.loadFromUri(rule_path)

        if self._debug:
            print("[INFO] Using ModSecurity CRS with PL = {} and INBOUND THRESHOLD = {}"
                    .format(pl, threshold)
            )


    def _process_query(self, payload: str):
        """
        Process the provided payload using the ModSecurity CRS WAF.

        Arguments:
        ----------
            payload: str
                The payload to process. 
        """
        # Create the rules logger
        rules_logger_cb = RulesLogger(
            threshold=self._threshold,
            debug=self._debug
        )
        # Set the rules logger callback to the ModSecurity CRS
        self._modsec.setServerLogCb2(
            rules_logger_cb, 
            LogProperty.RuleMessageLogProperty,
        )

        self._rules_logger_cb = rules_logger_cb

        # Remove encoding from the payload
        payload = quote_plus(payload)
        
        # Process the payload using the ModSecurity CRS
        transaction = Transaction(self._modsec, self._rules)
        transaction.processURI(
            "http://127.0.0.1/test?{}".format(payload), 
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
            self._process_query(x)
            return self._process_response()

        if isinstance(X, list) or len(X.shape) == 1:
            scores = np.array([process_and_get_prediction(x) for x in X])
        else:
            raise ValueError(
            "Invalid input shape. Expected 1D array or list, got {}D array"
                .format(len(X.shape))
            )
        
        return scores

    def _get_triggered_rules(self):
        """
        Returns the list of the triggered rules.

        Returns:
        --------
            list
                The list of the triggered rules.
        """
        return self._rules_logger_cb.get_triggered_rules()
    

class RulesLogger:
    _SEVERITY_SCORE = {
            2: 5,   # CRITICAL
            3: 4,   # ERROR
            4: 3,   # WARNING
            5: 2    # NOTICE
        }
    
    def _severity2score(self, severity):
        """
        Convert the severity to a score.

        Parameters:
        ----------
            severity: int
                The severity of the rule.
        
        Returns:
        --------
            score: float
                The score of the severity.
        """
        return self._SEVERITY_SCORE[severity]
    

    def __init__(self, threshold=5.0, regex_rules_filter=None, debug=False):
        """
        Constructor of RulesLogger class

        Parameters:
        ----------
            threshold: float
                The threshold to use
            regex_rules_filter: str
                The regular expression to filter the rules.
            debug: bool
                Flag to enable the debug mode.
        """
        self._rules_triggered = []
        self._debug           = debug
        self._rules_filter    = re.compile(regex_rules_filter) if regex_rules_filter is not None \
                                    else re.compile('^.*')
        self._score           = 0.0
        self._threshold       = threshold
        self._status          = 200


    def __call__(self, data, rule_message):
        """
        Callback function to log the ModSecurity rules triggered

        Parameters:
        ----------
            data: object
                The data to log.
            rule_message: object
                The message of the rule.
        """
        if self._debug:
            print('[DEBUG] PyModSecurity rule logger callback')
            print("[DEBUG] ID: {}, Message: {}, Phase: {}, Severity: {}".format(
                rule_message.m_ruleId, 
                rule_message.m_message, 
                rule_message.m_phase,
                rule_message.m_severity
            ))
 
        elif re.match(self._rules_filter, str(rule_message.m_ruleId)) and \
                (str(rule_message.m_ruleId) not in self._rules_triggered):
            self._rules_triggered.append(str(rule_message.m_ruleId))

        # Update the score
        self._score += self._severity2score(rule_message.m_severity)
        
        if self._score >= self._threshold:
            self._status = 403


    def get_triggered_rules(self):
        """
        Get the rules triggered
        
        Returns:
        --------
            rules: list
                The list of rules triggered.
        """
        return self._rules_triggered


    def get_score(self):
        """
        Get the score of the request
        
        Returns:
        --------
            score: float
                The score of the request.
        """
        return self._score
    
    def get_status(self):
        """
        Get the status of the request

        Returns:
        --------
            request_status: int
                The status of the request.
        """
        return self._status