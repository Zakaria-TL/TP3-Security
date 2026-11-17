# Part A results (auto-generated)

Records: 211043 | QIs: src_ip, dst_ip, src_port, dst_port, service | sensitive: type | max suppression: 5%

## k-anonymity vs linkage attack

| release | levels (src_ip/dst_ip/src_port/dst_port/service) | suppressed % | Prec loss | classes | avg class | min l-div | unique re-id % | attack type inferred % |
|---|---|---|---|---|---|---|---|---|
| raw | 0/0/0/0/0 | 0 | 0 | - | - | - | 50.4 | 98.6 |
| k=2, l>=1 | 0/0/1/0/0 | 3.47 | 0.0667 | 11504 | 17.71 | 1 | 0.0 | 79.0 |
| k=5, l>=1 | 0/0/1/1/0 | 3.4 | 0.1333 | 2470 | 82.54 | 1 | 0.0 | 73.0 |
| k=10, l>=1 | 1/0/1/1/0 | 3.51 | 0.1833 | 1538 | 132.4 | 1 | 0.0 | 61.2 |
| k=10, l>=2 | 1/4/2/3/0 | 3.67 | 0.5833 | 12 | 16941.75 | 2 | 0.0 | 0.0 |
| k=10, l>=3 | 1/4/2/3/0 | 3.93 | 0.5833 | 9 | 22528.56 | 5 | 0.0 | 0.0 |

## Differential privacy (mean of src_bytes per service, Laplace)

| epsilon | MAE_mean_bytes | weighted_rel_error_pct | MAE_count |
|---|---|---|---|
| 0.01 | 61408.906 | 10969.443 | 194.363 |
| 0.05 | 1508.259 | 269.42 | 38.015 |
| 0.1 | 226.207 | 40.407 | 20.32 |
| 0.5 | 37.121 | 6.631 | 3.888 |
| 1.0 | 18.617 | 3.325 | 2.06 |
| 5.0 | 4.163 | 0.744 | 0.411 |
| 10.0 | 2.049 | 0.366 | 0.2 |