
from typing import Dict, Any, List, Tuple
from collections import Counter
import numpy as np


class NGramFeatureExtractor:
    """Extract n-gram features from command sequences."""

    def __init__(self, n_range: Tuple[int, int] = (1, 3), top_k: int = 100):
        """
        Initialize extractor.

        Args:
            n_range: Tuple of (min_n, max_n) for n-gram sizes
            top_k: Number of top n-grams to keep as features
        """
        self.n_range = n_range
        self.top_k = top_k
        self.vocabulary: Dict[str, int] = {}
        self.is_fitted = False

    def fit(self, sessions: List[Dict[str, Any]]) -> 'NGramFeatureExtractor':
        """
        Build vocabulary from training sessions.

        Args:
            sessions: List of session dicts with 'commands' key

        Returns:
            Self for method chaining
        """
        all_ngrams = Counter()

        for session in sessions:
            commands = session.get("commands", [])
            for n in range(self.n_range[0], self.n_range[1] + 1):
                ngrams = self._extract_ngrams(commands, n)
                all_ngrams.update(ngrams)

        # Keep top_k most common n-grams
        top_ngrams = [ng for ng, _ in all_ngrams.most_common(self.top_k)]
        self.vocabulary = {ng: idx for idx, ng in enumerate(top_ngrams)}
        self.is_fitted = True

        return self

    def transform(self, sessions: List[Dict[str, Any]]) -> np.ndarray:
        """
        Transform sessions into n-gram feature vectors.

        Args:
            sessions: List of session dicts

        Returns:
            Feature matrix (n_samples x n_features)
        """
        if not self.is_fitted:
            raise RuntimeError("Extractor must be fitted before transform")

        features = []
        for session in sessions:
            session_ngrams = Counter()
            commands = session.get("commands", [])

            for n in range(self.n_range[0], self.n_range[1] + 1):
                ngrams = self._extract_ngrams(commands, n)
                session_ngrams.update(ngrams)

            # Create feature vector
            vector = np.zeros(len(self.vocabulary))
            for ngram, count in session_ngrams.items():
                if ngram in self.vocabulary:
                    vector[self.vocabulary[ngram]] = count

            features.append(vector)

        return np.array(features)

    def fit_transform(self, sessions: List[Dict[str, Any]]) -> np.ndarray:
        """Fit and transform in one step."""
        self.fit(sessions)
        return self.transform(sessions)

    def _extract_ngrams(self, commands: List[str], n: int) -> List[str]:
        """Extract n-grams from command list."""
        if len(commands) < n:
            return []

        # Use base commands (first token) for n-grams
        base_commands = []
        for cmd in commands:
            parts = cmd.split()
            if parts:
                base_commands.append(parts[0].lower())

        ngrams = []
        for i in range(len(base_commands) - n + 1):
            ngram = "|".join(base_commands[i:i+n])
            ngrams.append(ngram)

        return ngrams

    def get_feature_names(self) -> List[str]:
        """Get list of feature names (n-grams)."""
        if not self.is_fitted:
            return []
        return list(self.vocabulary.keys())
