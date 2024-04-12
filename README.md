# modsec-ml

## How to cite us

If you want to cite us, please use the following (BibTeX) reference:
```bibtex
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

In `modsec-ml` ModSecurity methods are implemented via [pymodsecurity](https://github.com/pymodsecurity/pymodsecurity).
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


