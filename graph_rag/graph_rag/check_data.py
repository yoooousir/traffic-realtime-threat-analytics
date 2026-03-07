import json

valid_events = []
invalid_count = 0

with open("./raw_data/eve.json") as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            valid_events.append(data)
        except json.JSONDecodeError:
            invalid_count += 1
            print(f"[WARN] line {i} 파싱 실패: {line[:50]}...")

print(f"✅ 정상: {len(valid_events)}개 / ❌ 손상: {invalid_count}개")
