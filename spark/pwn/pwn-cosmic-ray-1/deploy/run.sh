#!/bin/bash
docker run --rm -d \
  -p 9999:9999 \
  -e FLAG=flag{test_flag} \
  -e ROUND="1" \
  -e BLOCK_LIMIT="0" \
  --name cosmic-ray cosmic-ray:v2
