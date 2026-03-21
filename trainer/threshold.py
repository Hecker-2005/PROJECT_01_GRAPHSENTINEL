# threshold.py

import numpy as np

def compute_threshold(scores, percentile=90):
    """
    Determines the anomaly threshold based on the safe dataset scores.
    """
    threshold = np.percentile(scores, percentile)
    
    # Statistical logging for your project report
    mean_score = np.mean(scores)
    std_score = np.std(scores)
    
    print(f"--- Threshold Calibration ---")
    print(f"Safe Code Mean Error: {mean_score:.4f} ± {std_score:.4f}")
    print(f"Setting Anomaly Threshold at {percentile}th percentile: {threshold:.4f}")
    
    return threshold