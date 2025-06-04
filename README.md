SCA (Static Code Analysis) is a Python project that has scripts to statically analyze different code packages.
The scan uses regex looking through the code / projects passed in, to look for potential security vulnerabilities using the OWASP Top 10.

Currently the project has these scripts to analyze code:
* sca_cf.py (ColdFusion code/projects)
* sca_java.py (Java/Grails/Groovy code/projects)
## Reporting of results
Results are exported to a sortable HTML report.

# Running ColdFusion Audit
Running Cold Fusion static analysis script with HTML report results.

`cd to project root`

## Recommended HTML Report
`% python3 sca_cf.py --html-report results.html`

## Alternative Report Output
To run the cold fusion script, to audit a local files, outputting results **as JSON**:

`% python3 sca_cf.py >> results.json`

To capture output into **CSV format**:

`% python3 sca_cf.py -o results.csv`

# Running Java & Groovy/Grails Audit
To run the Grails/Groovy audit script, to audit local files:

`cd to project root`

## Recommended HTML Report

`% python3 sca_java.py --html-report results.html`

## Alternative Report Output
For **JSON only** output:

`% python3 sca_java.py >> java_results.json`

To capture output into **CSV format**:

`% python3 sca_java.py -o java_results.csv`

