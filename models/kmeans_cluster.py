
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import silhouette_score, calinski_harabasz_score, davies_bouldin_score
import logging

logger = logging.getLogger(__name__)


class KMeansCluster:
    """K-Means clustering with Z-score normalization and optimal K selection."""

    def __init__(self, 
                 n_clusters: int = 5,
                 auto_k: bool = True,
                 k_range: Tuple[int, int] = (2, 10),
                 random_state: int = 42):
        """
        Initialize K-Means clusterer.

        Args:
            n_clusters: Number of clusters (if auto_k=False)
            auto_k: Automatically find optimal K using elbow + silhouette
            k_range: Range of K values to test
            random_state: Random seed for reproducibility
        """
        self.n_clusters = n_clusters
        self.auto_k = auto_k
        self.k_range = k_range
        self.random_state = random_state

        self.model: Optional[KMeans] = None
        self.scaler = StandardScaler()
        self.label_encoders: Dict[str, LabelEncoder] = {}
        self.is_fitted = False

        # Metrics
        self.silhouette = 0.0
        self.calinski_harabasz = 0.0
        self.davies_bouldin = 0.0
        self.inertia = 0.0
        self.k_scores: Dict[int, Dict[str, float]] = {}

    def fit(self, X: np.ndarray, categorical_cols: Optional[List[int]] = None) -> 'KMeansCluster':
        """
        Fit K-Means model.

        Args:
            X: Feature matrix (n_samples x n_features)
            categorical_cols: Indices of categorical columns

        Returns:
            Self for method chaining
        """
        X_processed = self._preprocess(X, categorical_cols, fit=True)

        if self.auto_k:
            self.n_clusters = self._find_optimal_k(X_processed)
            logger.info(f"Auto-selected K={self.n_clusters}")

        self.model = KMeans(
            n_clusters=self.n_clusters,
            init='k-means++',
            n_init=10,
            max_iter=300,
            tol=1e-4,
            random_state=self.random_state
        )

        self.model.fit(X_processed)
        self.is_fitted = True

        # Compute metrics
        labels = self.model.labels_
        self.inertia = self.model.inertia_

        if len(set(labels)) > 1 and len(labels) > len(set(labels)):
            self.silhouette = silhouette_score(X_processed, labels)
            self.calinski_harabasz = calinski_harabasz_score(X_processed, labels)
            self.davies_bouldin = davies_bouldin_score(X_processed, labels)

        logger.info(f"K-Means fitted: inertia={self.inertia:.2f}, "
                   f"silhouette={self.silhouette:.3f}")

        return self

    def predict(self, X: np.ndarray, categorical_cols: Optional[List[int]] = None) -> np.ndarray:
        """Predict cluster labels for new data."""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before prediction")

        X_processed = self._preprocess(X, categorical_cols, fit=False)
        return self.model.predict(X_processed)

    def fit_predict(self, X: np.ndarray, categorical_cols: Optional[List[int]] = None) -> np.ndarray:
        """Fit and predict in one step."""
        self.fit(X, categorical_cols)
        return self.model.labels_

    def get_cluster_centers(self) -> np.ndarray:
        """Get cluster centers (in original feature space)."""
        if not self.is_fitted:
            raise RuntimeError("Model not fitted")
        return self.scaler.inverse_transform(self.model.cluster_centers_)

    def get_metrics(self) -> Dict[str, float]:
        """Return clustering metrics."""
        return {
            "silhouette_score": self.silhouette,
            "calinski_harabasz_index": self.calinski_harabasz,
            "davies_bouldin_index": self.davies_bouldin,
            "inertia": self.inertia,
            "n_clusters": self.n_clusters
        }

    def _preprocess(self, X: np.ndarray, 
                   categorical_cols: Optional[List[int]], 
                   fit: bool) -> np.ndarray:
        """Preprocess features: encode categoricals, Z-score normalize."""
        X = np.array(X)

        if categorical_cols:
            for col in categorical_cols:
                if fit:
                    le = LabelEncoder()
                    X[:, col] = le.fit_transform(X[:, col].astype(str))
                    self.label_encoders[col] = le
                else:
                    le = self.label_encoders.get(col)
                    if le:
                        X[:, col] = le.transform(X[:, col].astype(str))

        # Z-score normalization (Research DNA from Singh 2026)
        if fit:
            return self.scaler.fit_transform(X)
        return self.scaler.transform(X)

    def _find_optimal_k(self, X: np.ndarray) -> int:
        """Find optimal K using elbow method and silhouette score."""
        inertias = []
        silhouettes = []

        for k in range(self.k_range[0], self.k_range[1] + 1):
            kmeans = KMeans(n_clusters=k, random_state=self.random_state, n_init=10)
            labels = kmeans.fit_predict(X)

            inertia = kmeans.inertia_
            sil = silhouette_score(X, labels) if len(set(labels)) > 1 else 0.0

            inertias.append(inertia)
            silhouettes.append(sil)

            self.k_scores[k] = {
                "inertia": inertia,
                "silhouette": sil
            }

        # Select K with highest silhouette score
        best_k = range(self.k_range[0], self.k_range[1] + 1)[np.argmax(silhouettes)]
        return best_k
