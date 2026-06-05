import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict, Counter
import pickle
import logging

logger = logging.getLogger(__name__)


class MDPPredictor:
    """Markov Decision Process for predicting next attacker command."""

    def __init__(self, order: int = 2, smoothing: float = 0.1):
        """
        Initialize MDP predictor.

        Args:
            order: Markov chain order (1, 2, or 3)
            smoothing: Laplace smoothing parameter
        """
        self.order = order
        self.smoothing = smoothing

        # Transition matrices
        self.transitions = defaultdict(Counter)
        self.state_counts = Counter()
        self.vocabulary = set()
        self.is_fitted = False

        # Metrics
        self.perplexity = 0.0
        self.total_states = 0

    def fit(self, sessions):
        """Fit Markov model on training sessions."""
        logger.info(f"Fitting {self.order}-order Markov model...")

        for session in sessions:
            commands = session.get("commands", [])

            # Convert to base commands (first token)
            states = []
            for cmd in commands:
                parts = cmd.split()
                if parts:
                    states.append(parts[0].lower())

            if len(states) < self.order + 1:
                continue

            # Build transitions
            for i in range(len(states) - self.order):
                if self.order == 1:
                    state = (states[i],)
                elif self.order == 2:
                    state = (states[i], states[i+1])
                else:
                    state = (states[i], states[i+1], states[i+2])

                next_state = states[i + self.order]
                self.transitions[state][next_state] += 1
                self.state_counts[state] += 1
                self.vocabulary.add(next_state)

        self.is_fitted = True
        self.total_states = len(self.transitions)

        # Compute perplexity
        self.perplexity = self._compute_perplexity(sessions)

        logger.info(f"MDP fitted: {self.total_states} states, "
                   f"{len(self.vocabulary)} commands, perplexity={self.perplexity:.2f}")

        return self

    def predict(self, sequence, top_k=3):
        """Predict next command given a sequence."""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before prediction")

        # Extract base commands
        states = []
        for cmd in sequence:
            parts = cmd.split()
            if parts:
                states.append(parts[0].lower())

        if len(states) < self.order:
            return [(cmd, 1.0/len(self.vocabulary)) for cmd in list(self.vocabulary)[:top_k]]

        # Get state tuple
        if self.order == 1:
            state = (states[-1],)
        elif self.order == 2:
            state = (states[-2], states[-1])
        else:
            state = (states[-3], states[-2], states[-1])

        # Get transition probabilities
        transitions = self.transitions.get(state, Counter())
        total = self.state_counts[state] + self.smoothing * len(self.vocabulary)

        # Calculate probabilities with Laplace smoothing
        probs = {}
        for cmd in self.vocabulary:
            count = transitions.get(cmd, 0)
            probs[cmd] = (count + self.smoothing) / total

        # Return top_k predictions
        sorted_probs = sorted(probs.items(), key=lambda x: x[1], reverse=True)
        return sorted_probs[:top_k]

    def predict_next(self, sequence):
        """Predict single most likely next command."""
        predictions = self.predict(sequence, top_k=1)
        return predictions[0][0] if predictions else "unknown"

    def evaluate(self, sessions):
        """Evaluate model accuracy on test sessions."""
        top1_correct = 0
        top3_correct = 0
        total = 0
        log_likelihood = 0.0

        for session in sessions:
            commands = session.get("commands", [])
            states = [cmd.split()[0].lower() for cmd in commands if cmd.split()]

            if len(states) < self.order + 1:
                continue

            for i in range(len(states) - self.order):
                if self.order == 1:
                    state = (states[i],)
                elif self.order == 2:
                    state = (states[i], states[i+1])
                else:
                    state = (states[i], states[i+1], states[i+2])

                actual = states[i + self.order]
                predictions = self.predict(list(state), top_k=3)

                pred_commands = [p[0] for p in predictions]
                if actual == pred_commands[0]:
                    top1_correct += 1
                if actual in pred_commands:
                    top3_correct += 1

                total += 1

                # Log likelihood
                transitions = self.transitions.get(state, Counter())
                total_count = self.state_counts[state] + self.smoothing * len(self.vocabulary)
                prob = (transitions.get(actual, 0) + self.smoothing) / total_count
                log_likelihood += np.log(prob)

        perplexity = np.exp(-log_likelihood / total) if total > 0 else float('inf')

        return {
            "top1_accuracy": top1_correct / total if total > 0 else 0.0,
            "top3_accuracy": top3_correct / total if total > 0 else 0.0,
            "perplexity": perplexity,
            "total_predictions": total
        }

    def _compute_perplexity(self, sessions):
        """Compute model perplexity on training data."""
        log_likelihood = 0.0
        total = 0

        for session in sessions:
            commands = session.get("commands", [])
            states = [cmd.split()[0].lower() for cmd in commands if cmd.split()]

            if len(states) < self.order + 1:
                continue

            for i in range(len(states) - self.order):
                if self.order == 1:
                    state = (states[i],)
                elif self.order == 2:
                    state = (states[i], states[i+1])
                else:
                    state = (states[i], states[i+1], states[i+2])

                actual = states[i + self.order]
                transitions = self.transitions.get(state, Counter())
                total_count = self.state_counts[state] + self.smoothing * len(self.vocabulary)
                prob = (transitions.get(actual, 0) + self.smoothing) / total_count

                log_likelihood += np.log(prob)
                total += 1

        return np.exp(-log_likelihood / total) if total > 0 else float('inf')

    def save(self, filepath):
        """Save model to file."""
        with open(filepath, 'wb') as f:
            pickle.dump(self.__dict__, f)
        logger.info(f"Model saved to {filepath}")

    def load(self, filepath):
        """Load model from file."""
        with open(filepath, 'rb') as f:
            self.__dict__.update(pickle.load(f))
        logger.info(f"Model loaded from {filepath}")
