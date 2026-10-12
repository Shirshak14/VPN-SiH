# Autoencoder experiment

The original brief asked for a PyTorch autoencoder as the anomaly model. The deployed layer uses grouped Isolation Forests plus benign-envelope
statistics instead (see the README). This page records what happened when an autoencoder was actually tried, so the choice is evidence rather than omission.

**What was run.** `python -m experiments.autoencoder_eval` (from `backend/`, after `python -m synth.generate` and `python -m ipsec_analyzer.ml.train`).
It is **not PyTorch**: it uses scikit-learn's `MLPRegressor` trained to reproduce its own input through a bottleneck, so it needs no new dependency; the idea
is the same, the framework is not. Features are the deployed model's per-tunnel features (minus the two ESP ratios, which are constant zero in every benign
tunnel), `log1p`-transformed and standardised. It is fitted on the 140 benign training tunnels only. The score is mean squared reconstruction error averaged
over 3 seeds, and the threshold is the 99th percentile of 5-fold out-of-fold benign errors, exactly the rule the forests use. It is judged on the same 168
held-out tunnels as the deployed layer.

**Result** (simulated corpus, tunnels flagged / tunnels in family):

| Family | n | Deployed anomaly layer | Autoencoder (6) | Autoencoder (16-4-16) |
|---|---|---|---|---|
| a_half_open_scan | 6 | 6 | 6 | 6 |
| a_oversize_handshake | 6 | 6 | **0** | **0** |
| a_rekey_storm | 6 | 5 | 6 | 5 |
| a_retransmit_burst | 6 | 6 | 6 | 6 |
| a_slow_relay | 6 | 6 | 6 | 5 |
| a_esp_replay | 6 | 0 | 0 | 0 |
| d_dh_only / d_offer_strong_chose_weak | 12 | 0 | 11 | 12 |
| other weak-config and downgrade families (10 families, 60 tunnels) | 60 | 4 | 6 | 5 |
| **benign false alarms** (of 60) | 60 | 3 | 0 | 0 |
| **all positives caught** (of 108) | 108 | 34 | 43 | 40 |

**Reading it honestly.**

* On the behavioural families the autoencoder is **comparable, not better**: it gains one tunnel on rekey storms (6/6 vs 5/6, which is one sample in a family of six)
  and loses the whole oversize-handshake family (0/6 vs 6/6), because that family moves one feature a long way, which averages away in a reconstruction error across 27 features.
* Its extra catches on the downgrade families come from the `rank_drop` feature (offered vs chosen suite strength), which is a rule-engine signal the rules already catch (`SA-DOWNGRADE`, 6/6 each). That is not independent evidence for the autoencoder.
* The zero benign false alarms (vs 3) is the most interesting number, and also the least trustworthy one: 60 benign tunnels, all from a simulator we wrote.
* It would cost a second model to persist, calibrate and explain. Reconstruction error has no SHAP-style per-feature attribution that is as straightforward as a tree's, and the UI currently explains every alert.

**Decision.** Not adopted. The evidence does not justify the extra component: where it helps it is one tunnel, where it hurts it is a whole family. Revisit if
(a) real behavioural lab captures exist (the draft lab scenarios in this repo are the way to get them), (b) the benign corpus grows well beyond 140 tunnels, or
(c) the deployed layer's false-alarm rate is a problem on real traffic. The script is the starting point; wiring it in would mean adding it as another group in
`ml/model.py` calibrated like the forests, with its per-feature squared errors as the explanation.
