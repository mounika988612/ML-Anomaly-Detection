"""Unsupervised (Isolation Forest, PCA) and supervised (Random Forest) reference detectors."""
import numpy as np
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest, RandomForestClassifier


class IForest:
    def __init__(self, n_fit, trees, seed):
        self.n_fit, self.trees, self.seed = n_fit, trees, seed

    def fit(self, X):
        rs = np.random.RandomState(self.seed)
        sub = X[rs.choice(len(X), min(self.n_fit, len(X)), replace=False)]
        self.m = IsolationForest(n_estimators=self.trees, random_state=self.seed, n_jobs=-1).fit(sub)
        return self

    def score(self, X):
        return -self.m.score_samples(X)


class PCARecon:
    def __init__(self, n_fit, seed):
        self.n_fit, self.seed = n_fit, seed

    def fit(self, X):
        rs = np.random.RandomState(self.seed)
        sub = X[rs.choice(len(X), min(self.n_fit, len(X)), replace=False)]
        self.m = PCA(n_components=0.95, random_state=self.seed).fit(sub)
        return self

    def score(self, X):
        out = []
        for i in range(0, len(X), 100000):
            x = X[i:i + 100000]
            out.append(((x - self.m.inverse_transform(self.m.transform(x))) ** 2).mean(1))
        return np.concatenate(out)


class SupervisedRF:
    """Trained on labelled early-period attacks only, so it shows the zero-day generalisation gap."""

    def __init__(self, trees, seed):
        self.m = RandomForestClassifier(n_estimators=trees, max_depth=20, min_samples_leaf=2,
                                        class_weight="balanced_subsample", n_jobs=-1, random_state=seed)

    def fit(self, X, y):
        self.m.fit(X, y)
        return self

    def score(self, X):
        return self.m.predict_proba(X)[:, 1]
