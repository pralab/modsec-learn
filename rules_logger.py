
import re


class RulesLogger:
    def __init__(self, threshold=5.0, regex_rules_filter=None, debug=False):
        """
        Constructor of RulesLogger class

        Arguments:
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

        Arguments:
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

        if rule_message.m_ruleId == 949110:
            self._score = float(
                re.findall(r"\(Total Score: (\d+)\)",
                str(rule_message.m_message))[0]
            )
        
        elif re.match(self._rules_filter, str(rule_message.m_ruleId)) and \
                (str(rule_message.m_ruleId) not in self._rules_triggered):
            self._rules_triggered.append(str(rule_message.m_ruleId))
        
        if self._score >= self._threshold:
            self._status = 403


    def get_rules(self):
        """
        Get the rules triggered
        
        Returns:
        --------
            list
                The list of rules triggered.
        """
        return self._rules_triggered


    def get_score(self):
        """
        Get the score of the request
        
        Returns:
        --------
            float
                The score of the request.
        """
        return self._score
    
    def get_status(self):
        """
        Get the status of the request

        Returns:
        --------
            int
                The status of the request.
        """
        return self._status