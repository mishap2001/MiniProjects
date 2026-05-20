#!/bin/bash

# Usage: ./decoder.sh <payload_file>

MODEL="gpt-5.2"
INPUT="$1"

if [ -z "$INPUT" ] || [ ! -f "$INPUT" ]; then
  echo "Usage: $0 <payload_file>"
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "[!] jq is required. Install it with:"
  echo "    sudo apt install jq -y"
  exit 1
fi

BASE="$(basename "$INPUT")"
NAME="${BASE%.*}"
OUTDIR="${NAME}_decoded"
OUT="$OUTDIR/${NAME}_decoded.txt"
AI_JSON="$OUTDIR/${NAME}_ai_analysis.json"
AI_TXT="$OUTDIR/${NAME}_ai_analysis.txt"
SHELLCODE="$OUTDIR/${NAME}_shellcode.bin"

mkdir -p "$OUTDIR"
> "$OUT"

TMP1="$(mktemp)"
TMP2="$(mktemp)"
TMPB64="$(mktemp)"

LAUNCHER=$(grep -Eoi 'powershell(\.exe)?[[:space:]][^"<]+' "$INPUT" | head -n 1)

if [ -n "$LAUNCHER" ]; then
  {
    echo "POWERSHELL COMMAND:"
    echo
    echo "$LAUNCHER"
    echo
    echo "=================================================="
    echo
  } >> "$OUT"
fi

grep -Eoi '(-e|-enc|-encodedcommand)[[:space:]]+[A-Za-z0-9+/=]{80,}' "$INPUT" \
| awk '{print $2}' \
| head -n 1 \
| base64 -d 2>/dev/null \
| iconv -f UTF-16LE -t UTF-8 2>/dev/null > "$TMP1"

if [ ! -s "$TMP1" ]; then
  grep -oE '[A-Za-z0-9+/=]{80,}' "$INPUT" \
  | head -n 1 \
  | base64 -d 2>/dev/null \
  | iconv -f UTF-16LE -t UTF-8 2>/dev/null > "$TMP1"
fi

if [ ! -s "$TMP1" ]; then
  grep -oE '[A-Za-z0-9+/=]{20,}' "$INPUT" \
  | head -n 1 \
  | base64 -d 2>/dev/null > "$TMP1"
fi

if grep -q "GzipStream" "$TMP1"; then
  FORMAT_VALUES=$(grep -oE -- "-f''[^)]+" "$TMP1" | head -n 1)

  V0=$(echo "$FORMAT_VALUES" | awk -F"''" '{print $2}')
  V1=$(echo "$FORMAT_VALUES" | awk -F"''" '{print $4}')
  V2=$(echo "$FORMAT_VALUES" | awk -F"''" '{print $6}')

  perl -0777 -ne '
    while(/\x27\x27([A-Za-z0-9+\/{}=]+)\x27\x27/g){print $1}
  ' "$TMP1" > "$TMPB64"

  [ -n "$V0" ] && sed -i "s/{0}/$V0/g" "$TMPB64"
  [ -n "$V1" ] && sed -i "s/{1}/$V1/g" "$TMPB64"
  [ -n "$V2" ] && sed -i "s/{2}/$V2/g" "$TMPB64"

  base64 -d "$TMPB64" 2>/dev/null | gzip -dc > "$TMP2" 2>/dev/null
fi

{
  echo "DECODED PAYLOAD:"
  echo
  if [ -s "$TMP2" ]; then
    cat "$TMP2"
  elif [ -s "$TMP1" ]; then
    cat "$TMP1"
  else
    echo "[!] No readable decoded payload found."
  fi
  echo
} >> "$OUT"

if grep -q 'FromBase64String("' "$OUT"; then
  NESTED=$(grep -oE 'FromBase64String\("[A-Za-z0-9+/=]{80,}"\)' "$OUT" | head -n 1 | sed 's/FromBase64String("//;s/")//')

  if [ -n "$NESTED" ]; then
    echo "$NESTED" | base64 -d > "$SHELLCODE" 2>/dev/null

    if [ -s "$SHELLCODE" ]; then
      {
        echo
        echo "=================================================="
        echo "SHELLCODE STRINGS:"
        echo
        strings "$SHELLCODE"
      } >> "$OUT"
    fi
  fi
fi

rm -f "$TMP1" "$TMP2" "$TMPB64"

echo "[+] Decoded payload saved to:"
echo "    $OUT"

echo
read -p "[?] Upload decoded result to OpenAI for AI analysis? (y/n): " UPLOAD_AI

if [[ "$UPLOAD_AI" =~ ^[Yy]$ ]]; then
  read -s -p "[*] Enter OpenAI API key: " OPENAI_API_KEY
  echo
  echo "[*] Sending decoded payload to OpenAI..."

  PROMPT=$(cat <<EOF
You are a malware analyst. Analyze the decoded payload below.

Rules:
- Do not invent details.
- Explain the original command.
- Explain each function or major code block.
- Explain suspicious Windows APIs.
- Explain shellcode strings.
- If Base64 is binary shellcode and cannot become readable text, say so.
- Keep explanations clear and practical.

Decoded payload:
$(cat "$OUT")
EOF
)

  jq -n \
    --arg model "$MODEL" \
    --arg input "$PROMPT" \
    '{
      model: $model,
      input: $input,
      text: {
        format: {
          type: "json_schema",
          name: "payload_analysis",
          strict: true,
          schema: {
            type: "object",
            additionalProperties: false,
            properties: {
              type: { type: "string" },
              risk: { type: "string" },
              summary: { type: "string" },
              launcher_command: {
                type: "object",
                additionalProperties: false,
                properties: {
                  command: { type: "string" },
                  explanation: { type: "string" }
                },
                required: ["command", "explanation"]
              },
              functions: {
                type: "array",
                items: {
                  type: "object",
                  additionalProperties: false,
                  properties: {
                    name: { type: "string" },
                    purpose: { type: "string" }
                  },
                  required: ["name", "purpose"]
                }
              },
              suspicious_apis: {
                type: "array",
                items: {
                  type: "object",
                  additionalProperties: false,
                  properties: {
                    api: { type: "string" },
                    reason: { type: "string" }
                  },
                  required: ["api", "reason"]
                }
              },
              shellcode_analysis: {
                type: "object",
                additionalProperties: false,
                properties: {
                  is_shellcode: { type: "boolean" },
                  explanation: { type: "string" },
                  visible_strings: {
                    type: "array",
                    items: { type: "string" }
                  }
                },
                required: ["is_shellcode", "explanation", "visible_strings"]
              },
              verdict: { type: "string" }
            },
            required: [
              "type",
              "risk",
              "summary",
              "launcher_command",
              "functions",
              "suspicious_apis",
              "shellcode_analysis",
              "verdict"
            ]
          }
        }
      }
    }' > "$OUTDIR/request.json"

  RESPONSE=$(curl -s https://api.openai.com/v1/responses \
    -H "Authorization: Bearer $OPENAI_API_KEY" \
    -H "Content-Type: application/json" \
    -d @"$OUTDIR/request.json")

  echo "$RESPONSE" | jq -r '
    if .output_text then
      .output_text
    elif .output[0].content[0].text then
      .output[0].content[0].text
    elif .error then
      {"error": .error.message}
    else
      .
    end
  ' > "$AI_JSON"

  rm -f "$OUTDIR/request.json"

  jq -r '
    "Type: \(.type)",
    "Risk: \(.risk)",
    "",
    "Summary:",
    .summary,
    "",
    "Launcher Command:",
    .launcher_command.command,
    .launcher_command.explanation,
    "",
    "Functions:",
    (.functions[]? | "- \(.name): \(.purpose)"),
    "",
    "Suspicious APIs:",
    (.suspicious_apis[]? | "- \(.api): \(.reason)"),
    "",
    "Shellcode:",
    .shellcode_analysis.explanation,
    "",
    "Visible Strings:",
    (.shellcode_analysis.visible_strings[]? | "- \(.)"),
    "",
    "Verdict:",
    .verdict
  ' "$AI_JSON" > "$AI_TXT" 2>/dev/null

  echo "[+] AI JSON saved to:"
  echo "    $AI_JSON"
  echo "[+] AI readable analysis saved to:"
  echo "    $AI_TXT"
  echo
  cat "$AI_TXT"
fi

if [ -f "$SHELLCODE" ]; then
  echo
  echo "[+] Shellcode saved to:"
  echo "    $SHELLCODE"
fi
