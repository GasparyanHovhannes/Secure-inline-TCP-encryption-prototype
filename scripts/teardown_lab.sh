#!/usr/bin/env bash
for ns in pc1 dev1 dev2 pc2; do ip netns del $ns 2>/dev/null || true; done
echo "Lab removed."
