from pathlib import Path
from collections import Counter
import json

from analyze_mobility import decode_capture

folder = Path(sorted(Path("mobility_results").glob("auto_macip_*"))[-1])
manifest = json.loads((folder / "capture_manifest.json").read_text())

events = []
for capture in manifest["captures"]:
    events.extend(decode_capture(folder, capture))

print("Total Type-2 NLRIs:", len(events))
print("Breakdown:")
for key, count in sorted(Counter(
    (e["event_type"], e["ip_binding"], e["origin_class"])
    for e in events
).items()):
    print(key, count)

print("\nMAC/IP advertisements:")
for e in events:
    if e["event_type"] == "advertisement" and e["ip_binding"] == "mac_ip":
        print(e["source_router"], e["mac"], e["ip"], e["rd"])