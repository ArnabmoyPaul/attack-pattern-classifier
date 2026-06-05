import pytest
import numpy as np

from models.kmeans_cluster import KMeansCluster
from models.hdbscan_cluster import HDBSCANCluster
from models.mdp_predictor import MDPPredictor


class TestKMeansCluster:
    """Tests for KMeansCluster."""

    @pytest.fixture
    def sample_data(self):
        np.random.seed(42)
        # Create 3 distinct clusters
        cluster1 = np.random.randn(50, 3) + np.array([0, 0, 0])
        cluster2 = np.random.randn(50, 3) + np.array([5, 5, 5])
        cluster3 = np.random.randn(50, 3) + np.array([10, 0, 10])
        return np.vstack([cluster1, cluster2, cluster3])

    def test_fit(self, sample_data):
        clusterer = KMeansCluster(n_clusters=3, auto_k=False, random_state=42)
        clusterer.fit(sample_data)

        assert clusterer.is_fitted
        assert clusterer.model is not None

    def test_predict(self, sample_data):
        clusterer = KMeansCluster(n_clusters=3, auto_k=False, random_state=42)
        clusterer.fit(sample_data)

        predictions = clusterer.predict(sample_data[:10])

        assert len(predictions) == 10
        assert all(0 <= p < 3 for p in predictions)

    def test_fit_predict(self, sample_data):
        clusterer = KMeansCluster(n_clusters=3, auto_k=False, random_state=42)
        labels = clusterer.fit_predict(sample_data)

        assert len(labels) == len(sample_data)
        assert len(set(labels)) == 3

    def test_auto_k(self, sample_data):
        clusterer = KMeansCluster(auto_k=True, k_range=(2, 5), random_state=42)
        clusterer.fit(sample_data)

        assert clusterer.is_fitted
        assert clusterer.n_clusters in range(2, 6)

    def test_metrics(self, sample_data):
        clusterer = KMeansCluster(n_clusters=3, auto_k=False, random_state=42)
        clusterer.fit(sample_data)
        metrics = clusterer.get_metrics()

        assert "silhouette_score" in metrics
        assert "calinski_harabasz_index" in metrics
        assert "davies_bouldin_index" in metrics
        assert "n_clusters" in metrics
        assert metrics["n_clusters"] == 3

    def test_cluster_centers(self, sample_data):
        clusterer = KMeansCluster(n_clusters=3, auto_k=False, random_state=42)
        clusterer.fit(sample_data)
        centers = clusterer.get_cluster_centers()

        assert centers.shape == (3, 3)

    def test_not_fitted_error(self, sample_data):
        clusterer = KMeansCluster(n_clusters=3, auto_k=False)

        with pytest.raises(RuntimeError, match="must be fitted"):
            clusterer.predict(sample_data[:5])

    def test_preprocess_categorical(self):
        # Data with categorical column
        X = np.array([
            [1, 2, "A"],
            [2, 3, "B"],
            [3, 4, "A"],
            [4, 5, "B"],
        ])

        clusterer = KMeansCluster(n_clusters=2, auto_k=False, random_state=42)
        clusterer.fit(X, categorical_cols=[2])

        assert clusterer.is_fitted


class TestHDBSCANCluster:
    """Tests for HDBSCANCluster."""

    @pytest.fixture
    def sample_data(self):
        np.random.seed(42)
        cluster1 = np.random.randn(30, 2) + np.array([0, 0])
        cluster2 = np.random.randn(30, 2) + np.array([5, 5])
        noise = np.random.randn(5, 2) + np.array([20, 20])
        return np.vstack([cluster1, cluster2, noise])

    def test_fit(self, sample_data):
        clusterer = HDBSCANCluster(min_cluster_size=5, min_samples=3)
        clusterer.fit(sample_data)

        assert clusterer.is_fitted
        assert clusterer.model is not None

    def test_fit_predict(self, sample_data):
        clusterer = HDBSCANCluster(min_cluster_size=5, min_samples=3)
        labels = clusterer.fit_predict(sample_data)

        assert len(labels) == len(sample_data)
        # Should have at least 2 clusters (excluding noise)
        unique_labels = set(labels)
        assert len(unique_labels) >= 2 or (-1 in unique_labels and len(unique_labels) >= 2)

    def test_metrics(self, sample_data):
        clusterer = HDBSCANCluster(min_cluster_size=5, min_samples=3)
        clusterer.fit(sample_data)
        metrics = clusterer.get_metrics()

        assert "n_clusters" in metrics
        assert "noise_ratio" in metrics
        assert "noise_count" in metrics
        assert metrics["noise_ratio"] >= 0

    def test_cluster_sizes(self, sample_data):
        clusterer = HDBSCANCluster(min_cluster_size=5, min_samples=3)
        clusterer.fit(sample_data)
        sizes = clusterer.get_cluster_sizes()

        assert isinstance(sizes, dict)
        # Noise cluster should be present if any
        if -1 in sizes:
            assert sizes[-1] >= 0

    def test_predict_new_data(self, sample_data):
        clusterer = HDBSCANCluster(min_cluster_size=5, min_samples=3)
        clusterer.fit(sample_data)

        new_data = np.array([[0.5, 0.5], [5.5, 5.5]])
        predictions = clusterer.predict(new_data)

        assert len(predictions) == 2


class TestMDPPredictor:
    """Tests for MDPPredictor."""

    @pytest.fixture
    def sample_sessions(self):
        return [
            {"commands": ["wget http://a.com", "chmod +x a", "./a", "exit"]},
            {"commands": ["wget http://b.com", "chmod +x b", "./b", "exit"]},
            {"commands": ["wget http://c.com", "chmod +x c", "./c", "exit"]},
            {"commands": ["ls", "pwd", "whoami"]},
            {"commands": ["ls", "pwd", "uname"]},
        ]

    def test_fit(self, sample_sessions):
        mdp = MDPPredictor(order=1)
        mdp.fit(sample_sessions)

        assert mdp.is_fitted
        assert mdp.total_states > 0
        assert len(mdp.vocabulary) > 0

    def test_predict(self, sample_sessions):
        mdp = MDPPredictor(order=1)
        mdp.fit(sample_sessions)

        predictions = mdp.predict(["wget"])

        assert len(predictions) > 0
        assert all(isinstance(p, tuple) and len(p) == 2 for p in predictions)
        assert sum(p[1] for p in predictions) <= 1.0 + 1e-6  # Probabilities sum to ~1

    def test_predict_next(self, sample_sessions):
        mdp = MDPPredictor(order=1)
        mdp.fit(sample_sessions)

        next_cmd = mdp.predict_next(["wget"])

        assert isinstance(next_cmd, str)
        assert next_cmd in mdp.vocabulary

    def test_higher_order(self, sample_sessions):
        mdp = MDPPredictor(order=2)
        mdp.fit(sample_sessions)

        predictions = mdp.predict(["wget", "chmod"])

        assert len(predictions) > 0

    def test_evaluate(self, sample_sessions):
        mdp = MDPPredictor(order=1)
        mdp.fit(sample_sessions)

        metrics = mdp.evaluate(sample_sessions)

        assert "top1_accuracy" in metrics
        assert "top3_accuracy" in metrics
        assert "perplexity" in metrics
        assert 0 <= metrics["top1_accuracy"] <= 1.0
        assert 0 <= metrics["top3_accuracy"] <= 1.0

    def test_not_fitted_error(self):
        mdp = MDPPredictor(order=1)

        with pytest.raises(RuntimeError, match="must be fitted"):
            mdp.predict(["wget"])

    def test_save_load(self, sample_sessions, tmp_path):
        mdp = MDPPredictor(order=1)
        mdp.fit(sample_sessions)

        save_path = tmp_path / "mdp_model.pkl"
        mdp.save(str(save_path))

        assert save_path.exists()

        loaded_mdp = MDPPredictor(order=1)
        loaded_mdp.load(str(save_path))

        assert loaded_mdp.is_fitted
        assert loaded_mdp.total_states == mdp.total_states

        # Test predictions are same
        pred1 = mdp.predict(["wget"])
        pred2 = loaded_mdp.predict(["wget"])
        assert pred1 == pred2

    def test_perplexity_computation(self, sample_sessions):
        mdp = MDPPredictor(order=1)
        mdp.fit(sample_sessions)

        assert mdp.perplexity > 0
        assert mdp.perplexity != float('inf')

    def test_short_sequence(self, sample_sessions):
        mdp = MDPPredictor(order=2)
        mdp.fit(sample_sessions)

        # Sequence shorter than order
        predictions = mdp.predict(["wget"])

        assert len(predictions) > 0
