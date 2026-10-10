import base64
i = 0
while i < 103: i += 1
print(f"moectf{{{base64.b64decode('cHl0aG9u').decode()}-{chr(i+2)}5-c0Ol}}")