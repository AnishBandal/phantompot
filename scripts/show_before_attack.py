import json

sessions = []
try:
    with open('logs/sessions.jsonl', 'r') as f:
        for line in f:
            if line.strip():
                sessions.append(json.loads(line))
except FileNotFoundError:
    sessions = []

total = len(sessions)
attacks = sum(1 for s in sessions if s.get('classification') == 'attack')
normal = sum(1 for s in sessions if s.get('classification') != 'attack')

print('BEFORE ATTACK:')
print(f'  Total sessions: {total}')
print(f'  Attacks: {attacks}')
print(f'  Normal: {normal}')
