"""
A wrapper for Scikit-learn classifiers.
"""

import os
import numpy as np
import joblib

from src.utils import type_check, file_exists
from src.exceptions import NotSklearnModelError, SklearnInternalError


class SklearnModelWrapper():
    """Scikit learn classifier wrapper class"""

    def __init__(self, model):
        """
        Constructs a wrapper around an scikit-learn classifier, or equivalent.
        It must implement predict_proba and fit function.
        
        Parameters:
        ----------
            sklearn_classifier (sci-kit learn classifier):  
                scikit-learn classifier or equivalent
        
        Raises:
        -------
            NotSklearnModelError: Not implement predict_proba

        Returns:
        --------
            self: object
        """
       
        if getattr(model, "predict_proba", None) is None:
            raise NotSklearnModelError(
                "Object does not implement predict_proba function"
            )

        self._model = model


    def fit(self, X, y):
        """
        Predict confidence scores for samples.

        Parameters:
        ----------
            X: ndarray of shape (n_samples, n_features): 
                The training input samples.
            y: ndarray of shape (n_samples,): 
                The target values.

        Returns:
        --------
            self: object
        """
        try:
            self._model.fit(X, y)
        except Exception as e:
            raise SklearnInternalError("Internal sklearn error.") from e
        return self


    def predict(self, X):
        """
        Predict class labels for samples in X.
        
        Parameters:
        ----------
            X: ndarray of shape (n_samples, n_features): 
                An input belonging to the input space of the model

        Returns:
        --------
            y_pred : ndarray of shape (n_samples,)
                Vector containing the class labels for each sample.
        """
        try:
            y_pred = self._model.predict_proba(X)
            return y_pred
        except Exception as e:
            raise SklearnInternalError("Internal sklearn error.") from e
   
   
    # FIXME: It doesn't work with the current implementation
    def load(self, file_path):
        """Loads a sklearn classifier stored in filepath.
        
        Parameters:
        ----------
            file_path: str
                The path of the sklearn classifier.

        Raises:
        -------
            TypeError: 
                `file_path` is not a string.
            FileNotFoundError: 
                `file_path` not pointing to any file.
            NotSklearnModelError: 
                The provided model can not be loaded.

        Returns:
        --------
            self: object
        """
        type_check(file_path, str, "file_path")
        file_exists(file_path)

        try:
            self._model = joblib.load(file_path)
        except Exception as e:
            raise NotSklearnModelError("Error in loading model.") from e
        return self