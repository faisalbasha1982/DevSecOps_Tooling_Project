python3 -c 'import json;d=json.load(open("artifacts/sast.sarif"));r=d["runs"][0];print(d["version"],len(r["results"]),"results",len(r["tool"]["driver"]["rules"]),"rules")'
# 2.1.0 4 results 3 rules
