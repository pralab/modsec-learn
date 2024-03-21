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

    def __init__(self, rules_dir, pl, crs_rules_ids):
        """
        Constructor of PyModsecurity class
        
        Arguments
        ---------
            rules_dir :str
                Path to the directory containing the CRS rules.
            pl: int             
                The Paranoia Level to use.
            crs_rules_ids: list 
                The list of the CRS rules ids to use.

        """
        self._modsec     = ModSecurity()
        self._rules      = RulesSet()
        base_path        = os.path.abspath(rules_dir)
        config_rule_file = "./modsec_config/REQUEST-901-INITIALIZATION_PL{pl}_THR5.conf"

        self._rules.loadFromUri(config_rule_file.format(pl=pl))
        
        try:
            for file_name in PyModSecurity._SELECTED_RULES_FILES:
                self._rules.loadFromUri(os.path.join(base_path, file_name))
        except OSError as error:
            raise SystemExit(
                "Error loading the rules for PyModsecurity: {}".format(error)
            )
        
        self._crs_rules_ids = crs_rules_ids

        error_str = self._rules.getParserError()
        if error_str != '':
            raise SystemExit(
                "Error parsing the rules: {}".format(error_str)
            )

        print("[INFO] Using ModSecurity CRS with PL = {}".format(pl))


    def process_queries(self, queries):
        """
        Process the queries and return the features and the scores

        Arguments
        ----------
            queries : list
                The list of queries to process.

        Returns
        -------
            features : numpy.ndarray
                The features extracted from the queries.
            scores : list
                The scores of the queries.

        """
        requests_info = []
        scores        = []

        for query in queries:
            rules_logger_cb = RulesLogger(regex_rules_filter="^942", debug=True)
            self._modsec.setServerLogCb2(rules_logger_cb, LogProperty.RuleMessageLogProperty)

            # TODO: Se ci fossero multipli encoding, bisognerebbe fare un loop??
            query = quote_plus(query)

            transaction = Transaction(self._modsec, self._rules)        
            transaction.processURI("http://127.0.0.1:80?data={}".format(query), "GET", "1.1")
            transaction.processRequestHeaders()
            transaction.processRequestBody()

            requests_info.append({
                "payload": query,
                "rules"  : rules_logger_cb.get_rules(),
                "score"  : rules_logger_cb.get_score()
            })
            
            scores.append(rules_logger_cb.get_score())

        # Estraggo le features
        features = self._onehot_convert(requests_info)
        
        return features, scores
    

    def _onehot_convert(self, requests_info):
        """
        Remap each rule ID to a new numerical ID used as column index of the dataset matrix
        This is needed because OWASP rule IDs range in [900,000 999,999] and each rule ID must be
        remapped to [0, N], where N is the length of owasp_rules list (which can be a sub-set
        of the whole OWASP CRS.
        For example, if considering only OWASP CRS rules against SQL-i are that are defined in the 
        942,000 - 942,999 block, they are re-mapped to [0, 999]

        Arguments:
        ----------
            request_info: list
                The list of requests information.
        
        Returns:
        --------
            features: numpy.ndarray
                The features extracted from the requests.

        """
        num_rules    = len(self._crs_rules_ids)
        num_requests = len(requests_info)
        
        features     = np.zeros((num_requests, num_rules))
        
        for idx, request in enumerate(requests_info):
            for rule in request['rules']:
                features[idx, self._crs_rules_ids.index(rule)] = 1

        return features
    


class PyModSecurityWaf():
    """PyModSecurity WAF wrapper"""

    _BAD_STATUS_CODES = [401, 403]
    _GOOD_STATUS_CODES = list(range(200, 209))
    _SELECTED_RULES_FILES = [
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        "REQUEST-949-BLOCKING-EVALUATION.conf"
    ]

    def __init__(self, rules_dir, threshold=5.0, pl=1, output_type='score'):
        """
        Constructor of PyModsecurityWaf class
        
        Arguments:
            url (str) : URL to connect to the WAF
            output_type (str) : type of output (supported values: "binary" or "scores")

        Raises:
            TypeError: if the type of any input argument is not valid
            ValueError: if the value of any input argument is not valid
        """
        type_check(rules_dir, str, 'rules_dir')
        self._modsec = ModSecurity()
        self._rules = RulesSet()
        self._rules_logger_callback = None
        base_path = os.path.abspath(rules_dir)
        config_rule_file = "REQUEST-901-INITIALIZATION_PL{pl}_THR{thr}.conf"

        type_check(threshold, float, 'threshold')
        self._threshold = threshold
        type_check(pl, int, 'pl')

        self._rules.loadFromUri(config_rule_file.format(pl=pl, thr=int(threshold)))

        try:
            for file_name in PyModSecurityWaf._SELECTED_RULES_FILES:
                self._rules.loadFromUri(os.path.join(base_path, file_name))
        except OSError as error:
            raise SystemExit("Error loading the rules for PyModsecurity: {}".format(error))

        error_str = self._rules.getParserError()
        if error_str != '':
            raise SystemExit("Error parsing the rules: {}".format(error_str))

        print("[INFO] Using ModSecurity CRS with PL = {}, inbound threshold = {}".format(pl, self._threshold))

        type_check(output_type, str, 'output_type')
        if output_type not in ['binary', 'score']:
            raise ValueError("Invalid value for mode input param: {}. Valid values are: ['binary', 'score']".format(output_type))
        self._output_type = output_type
    
    def send_request(self, payload):
        """
        Builds and sends a HTTP request to ModSecurity CRS WAF available as a Web Sandbox.

        Arguments:
            payload (str) : Payload to be sent with the HTTP request.
        """

        rules_logger_cb = RulesLogger(threshold=self._threshold)
        self._modsec.setServerLogCb2(rules_logger_cb, LogProperty.RuleMessageLogProperty)
        self._rules_logger_cb = rules_logger_cb

        transaction = Transaction(self._modsec, self._rules)
        payload = quote_plus(payload)
        transaction.processURI("http://127.0.0.1:80?data={}".format(payload), "GET", "HTTP/1.1")
        transaction.processRequestHeaders()
        transaction.processRequestBody()
        # status_code = 403 if transaction.intervention(intervention) else 200
        # transaction.processResponseHeaders(status_code, 'HTTP/1.1')
        # transaction.processResponseBody()
        # transaction.processLogging()

    def process_response(self):
        """
        Processes the HTTP response received from the ModSecurity CRS

        Arguments:
            response (requests.Response object) : The received response.
        """
        if self._rules_logger_cb is not None:
            # print("[DEBUG] Rules triggered: {}\n".format(self._rules_logger_cb.get_rules()))
            if self._output_type == 'binary':
                if self._rules_logger_cb.get_status() in PyModSecurityWaf._BAD_STATUS_CODES:
                    return 1.0
                else:
                    return 0.0
            else:  # self._output_type == 'score'
                return self._rules_logger_cb.get_score()
        else:
            raise SystemExit("Callback to process rules not initialized")

    def classify(self, value):
        """
        It returns the probability of being a malicious payload.
        
        Arguments:
            value (str) : input payload

        Returns:
            float : probability of being a malicious payload.
        """
        # build and send an HTTP request to the WAF:
        self.send_request(value)
        # process the response and compute the score
        score = self.process_response()
        return score

    def get_triggered_rules(self):
        return self._rules_logger_cb.get_rules()