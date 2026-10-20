import json

sessions = []
try:
    with open('logs/sessions.jsonl', 'r') as f:
        for line in f:
            if line.strip():
                sessions.append(json.loads(line))
except FileNotFoundError:
    sessions = []

attacks = [s for s in sessions if s.get('classification') == 'attack']

if attacks:
    print('\nFirst Attack Session:')
    print('='*60)
    print(json.dumps(attacks[0], indent=2))
    print('='*60)
else:
    print('No attacks found in logs yet')
