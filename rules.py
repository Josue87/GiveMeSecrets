from re import compile

def get_rules():
    # Rules from: https://github.com/dxa4481/truffleHog/blob/dev/scripts/searchOrg.py
    some_rules = {
            "Slack Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
            "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
            "SSH (OPENSSH) private key": "-----BEGIN OPENSSH PRIVATE KEY-----",
            "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
            "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
            "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "Facebook Oauth": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]",
            "Twitter Oauth": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]",
            "GitHub": "[g|G][i|I][t|T][h|H][u|U][b|B].{0,30}['\"\\s][0-9a-zA-Z]{35,40}['\"\\s]",
            "Google Oauth": "(\"client_secret\":\"[a-zA-Z0-9-_]{24}\")",
            "AWS API Key": "AKIA[0-9A-Z]{16}",
            "Heroku API Key": "[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
            "Generic Secret": "[s|S][e|E][c|C][r|R][e|E][t|T].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]",
            "Generic API Key": "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]",
            "Slack Webhook": "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
            "Google (GCP) Service-account": "\"type\": \"service_account\"",
            "Twilio API Key": "SK[a-z0-9]{32}",
            "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
            "AWS Client ID": "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
            "PKCS8": '-----BEGIN PRIVATE KEY-----'
        }
    my_rules = {}
    for key, rule in some_rules.items():
        try:
            my_rules[key] =  compile(rule)
        except:
            pass
    return my_rules
