import json
from collections import defaultdict

sessions = []
try:
    with open('logs/sessions.jsonl', 'r') as f:
        for line in f:
            if line.strip():
                sessions.append(json.loads(line))
except FileNotFoundError:
    sessions = []

attacks_by_protocol = defaultdict(list)

for s in sessions:
    if s.get('classification') == 'attack':
        attacks_by_protocol[s.get('protocol', 'unknown')].append(s)

print('\nATTACKS DETECTED BY PROTOCOL:')
print('='*50)
for protocol in sorted(attacks_by_protocol.keys()):
    attacks = attacks_by_protocol[protocol]
    print(f'{protocol.upper()}: {len(attacks)} attacks')
    for i, attack in enumerate(attacks[:2], 1):
        score = attack.get('ml_score', 0)
        commands = len(attack.get('commands', []))
        print(f'  {i}. Score: {score:.4f}, Commands: {commands}')
    if len(attacks) > 2:
        print(f'  ... and {len(attacks)-2} more')
print('='*50 + '\n')
