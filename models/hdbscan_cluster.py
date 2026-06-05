
import numpy as np
from typing import Dict, Any, List, Optional
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score, calinski_harabasz_score, davies_bouldin_score
import logging

logger = logging.getLogger(__name__)


class HDBSCANCluster:
    """HDBSCAN clustering for density-based attack pattern detection."""

    def __init__(self,
                 min_cluster_size: int = 5,
                 min_samples: int = 3,
                 metric: str = 'euclidean',
                 cluster_selection_method: str = 'eom'):
        """
        Initialize HDBSCAN clusterer.

        Args:
            min_cluster_size: Minimum points per cluster
            min_samples: Core point neighborhood size
            metric: Distance metric
            cluster_selection_method: 'eom' (Excess of Mass) or 'leaf'
        """
        self.min_cluster_size = min_cluster_size
        self.min_samples = min_samples
        self.metric = metric
        self.cluster_selection_method = cluster_selection_method

        self.model = None
        self.scaler = StandardScaler()
        self.is_fitted = False

        # Metrics
        self.silhouette = 0.0
        self.calinski_harabasz = 0.0
        self.davies_bouldin = 0.0
        self.noise_ratio = 0.0

    def fit(self, X: np.ndarray) -> 'HDBSCANCluster':
        """
        Fit HDBSCAN model.

        Args:
            X: Feature matrix

        Returns:
            Self for method chaining
        """
        try:
            import hdbscan
        except ImportError:
            raise ImportError("hdbscan package required. Install: pip install hdbscan")

        X_scaled = self.scaler.fit_transform(X)

        self.model = hdbscan.HDBSCAN(
            min_cluster_size=self.min_cluster_size,
            min_samples=self.min_samples,
            metric=self.metric,
            cluster_selection_method=self.cluster_selection_method,
            prediction_data=True
        )

        self.model.fit(X_scaled)
        self.is_fitted = True

        labels = self.model.labels_
        n_noise = np.sum(labels == -1)
        self.noise_ratio = n_noise / len(labels) if len(labels) > 0 else 0.0

        # Compute metrics (excluding noise points)
        mask = labels != -1
        if np.sum(mask) > 0 and len(set(labels[mask])) > 1:
            self.silhouette = silhouette_score(X_scaled[mask], labels[mask])
            self.calinski_harabasz = calinski_harabasz_score(X_scaled[mask], labels[mask])
            self.davies_bouldin = davies_bouldin_score(X_scaled[mask], labels[mask])

        n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
        logger.info(f"HDBSCAN fitted: {n_clusters} clusters, {self.noise_ratio:.1%} noise, "
                   f"silhouette={self.silhouette:.3f}")

        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict cluster labels for new data."""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before prediction")

        import hdbscan
        X_scaled = self.scaler.transform(X)
        if hasattr(hdbscan, "approximate_predict"):
            labels, _ = hdbscan.approximate_predict(self.model, X_scaled)
            return labels

        raise RuntimeError("Installed hdbscan does not support approximate_predict")

    def fit_predict(self, X: np.ndarray) -> np.ndarray:
        """Fit and predict in one step."""
        self.fit(X)
        return self.model.labels_

    def get_metrics(self) -> Dict[str, Any]:
        """Return clustering metrics."""
        labels = self.model.labels_ if self.model else np.array([])
        n_clusters = len(set(labels)) - (1 if -1 in labels else 0)

        return {
            "silhouette_score": self.silhouette,
            "calinski_harabasz_index": self.calinski_harabasz,
            "davies_bouldin_index": self.davies_bouldin,
            "n_clusters": n_clusters,
            "noise_ratio": self.noise_ratio,
            "noise_count": int(np.sum(labels == -1)) if len(labels) > 0 else 0,
            "min_cluster_size": self.min_cluster_size,
            "min_samples": self.min_samples
        }

    def get_cluster_sizes(self) -> Dict[int, int]:
        """Get size of each cluster."""
        if not self.is_fitted:
            return {}

        labels = self.model.labels_
        unique, counts = np.unique(labels, return_counts=True)
        return dict(zip(unique.tolist(), counts.tolist()))
