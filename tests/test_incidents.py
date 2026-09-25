import numpy as np

from ids_pipeline.evaluate import false_alerts_per_hour, incidents, min_p


def test_incidents_split_on_pauses_and_count_first_alert():
    # Bot: flows at 0,10,20 (incident 1) and 1000,1010 (incident 2, after a 980 s pause); DoS: one flow at 50
    ts = np.array([0, 10, 20, 50, 1000, 1010, 3600], float)
    label = np.array(["Bot", "Bot", "Bot", "DoS", "Bot", "Bot", "Benign"])
    y = (label != "Benign").astype(int)
    pred = np.array([False, False, True, False, False, False, True])
    day = np.array(["d"] * 7)
    inc = incidents(ts, y, label, day, pred, gap=300).sort_values(["attack", "start"])
    assert list(inc.attack) == ["Bot", "Bot", "DoS"]
    assert list(inc.n_flows) == [3, 2, 1]
    assert list(inc.detected) == [True, False, False]
    assert inc.seconds_to_detect.iloc[0] == 20.0 and np.isnan(inc.seconds_to_detect.iloc[1])
    # one benign alert over one hour of traffic
    assert false_alerts_per_hour(ts, y, day, pred) == 1.0


def test_min_p_fusion_keeps_each_views_evidence_at_target_fpr():
    rs = np.random.RandomState(0)
    ref_a, ref_b = rs.normal(size=20000), rs.lognormal(2.0, 1.5, size=20000)     # very different score scales
    base = min_p([ref_a, ref_b], [ref_a, ref_b])
    thr = np.quantile(base, 0.99)
    ben_a, ben_b = rs.normal(size=20000), rs.lognormal(2.0, 1.5, size=20000)
    assert abs((min_p([ben_a, ben_b], [ref_a, ref_b]) > thr).mean() - 0.01) < 0.005
    # an attack extreme in only one view is caught whichever view it is, despite the scale difference
    only_a = min_p([np.full(10, 6.0), np.full(10, np.median(ref_b))], [ref_a, ref_b])
    only_b = min_p([np.zeros(10), np.full(10, ref_b.max() * 2)], [ref_a, ref_b])
    assert (only_a > thr).all() and (only_b > thr).all()
