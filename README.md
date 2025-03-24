# modsec-learn

## How to cite us

If you want to cite us, please use the following (BibTeX) reference:
```BibTex
@InProceedings{10.1007/978-3-031-76459-2_3,
author="Scano, Christian
and Floris, Giuseppe
and Montaruli, Biagio
and Demetrio, Luca
and Valenza, Andrea
and Compagna, Luca
and Ariu, Davide
and Piras, Luca
and Balzarotti, Davide
and Biggio, Battista",
editor="Mehmood, Rashid
and Hern{\'a}ndez, Guillermo
and Pra{\c{c}}a, Isabel
and Wikarek, Jaroslaw
and Loukanova, Roussanka
and Monteiro dos Reis, Ars{\'e}nio
and Skarmeta, Antonio
and Lombardi, Eleonora",
title="ModSec-Learn: Boosting ModSecurity with Machine Learning",
booktitle="Distributed Computing and Artificial Intelligence, Special Sessions I, 21st International Conference",
year="2025",
publisher="Springer Nature Switzerland",
address="Cham",
pages="23--33",
isbn="978-3-031-76459-2"
}


```
## Getting started

### Setup

1. [Compile and install ModSecurity v3.0.10](#compile-modsecurity-v3010)
2. [Install pymodsecurity](#install-pymodsecurity)
3. [Clone the OWASP CoreRuleSet](#clone-the-owasp-coreruleset)
4. [Run experiments](#run-experiments)

### Compile ModSecurity v3.0.10 

First of all, you will need to install [ModSecurity v3.0.10](https://github.com/SpiderLabs/ModSecurity/releases/tag/v3.0.10) on your system.
Currently, this is a tricky process, since you will need to [build ModSecurity v3.0.10 from source](https://github.com/SpiderLabs/ModSecurity/wiki/Compilation-recipes-for-v3.x)
(although some distros might have an updated registry with ModSecurity 3.0.10 already available)

### Install pymodsecurity

In `modsec-learn` ModSecurity methods are implemented via [pymodsecurity](https://github.com/pymodsecurity/pymodsecurity).
Since development on the official repository stopped on ModSecurity v3.0.3, the current workaround is: clone [this fork](https://github.com/AvalZ/pymodsecurity) and [build it from source](https://github.com/AvalZ/pymodsecurity#building-from-source)

### Clone the OWASP CoreRuleSet

To detect incoming payloads, you need a Rule Set.
The *de facto* standard is the [OWASP CoreRuleSet](https://github.com/coreruleset/coreruleset), but of course, you can choose any Rule Set you want, or customize the OWASP CRS.

To run the recommended settings, just clone the OWASP CRS in the project folder:
```
git clone --branch v4.0.0 git@github.com:coreruleset/coreruleset.git
```

### Run experiments

All experiments can be executed using the Python scripts within the `scripts` folder. The scripts must be executed starting from the project's root.
```bash
python3 scripts/run_experiments.py

```


