
#!/bin/bash
###############################################################################
# CloudWatch Log Group KMS(CMK) 일괄 적용 스크립트
# - 환경: AWS CloudShell
# - KMS Alias: CloudWatchLogs_KMS2
###############################################################################
set -euo pipefail

REGION=$(aws configure get region 2>/dev/null || echo "ap-northeast-2")
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
KMS_ALIAS="alias/CloudWatchLogs_KMS2"

echo "=============================================="
echo " CloudWatch Log Group KMS 암호화 적용 스크립트"
echo "=============================================="
echo "Region  : $REGION"
echo "Account : $ACCOUNT_ID"
echo ""

# ─────────────────────────────────────────────────
# 1단계: KMS 미적용 로그 그룹 조회
# ─────────────────────────────────────────────────
echo "[1/4] KMS 미적용 로그 그룹 조회 중..."

ALL_GROUPS=()
ALL_KMS=()
UNENCRYPTED=()
NEXT_TOKEN=""
while true; do
  PAGINATE_ARGS=()
  [[ -n "$NEXT_TOKEN" ]] && PAGINATE_ARGS+=(--starting-token "$NEXT_TOKEN")

  RESPONSE=$(aws logs describe-log-groups "${PAGINATE_ARGS[@]}" --output json 2>/dev/null)

  while IFS=$'\t' read -r name kms; do
    [[ -z "$name" ]] && continue
    ALL_GROUPS+=("$name")
    ALL_KMS+=("${kms:-None}")
    [[ "$kms" == "None" || -z "$kms" ]] && UNENCRYPTED+=("$name")
  done < <(echo "$RESPONSE" \
    | python3 -c "
import sys, json
data = json.load(sys.stdin)
for lg in data.get('logGroups', []):
    name = lg['logGroupName']
    kms = lg.get('kmsKeyId') or 'None'
    print(f'{name}\t{kms}')
")

  NEXT_TOKEN=$(echo "$RESPONSE" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('nextToken',''))" 2>/dev/null)
  [[ -z "$NEXT_TOKEN" ]] && break
done

echo "  전체 로그 그룹: ${#ALL_GROUPS[@]}개 (KMS 적용: $(( ${#ALL_GROUPS[@]} - ${#UNENCRYPTED[@]} ))개 / 미적용: ${#UNENCRYPTED[@]}개)"
echo ""

if [[ ${#UNENCRYPTED[@]} -eq 0 ]]; then
  echo "  ✅ 모든 로그 그룹에 KMS가 적용되어 있습니다."
  echo ""
  echo "  ┌──────────────────────────────────────────────────────────────┬──────────────────────────────────┐"
  printf "  │ %-60s │ %-32s │\n" "Log Group" "KMS Key ID"
  echo "  ├──────────────────────────────────────────────────────────────┼──────────────────────────────────┤"
  for i in "${!ALL_GROUPS[@]}"; do
    KEY_SHORT="${ALL_KMS[$i]}"
    [[ "$KEY_SHORT" =~ key/(.+)$ ]] && KEY_SHORT="${BASH_REMATCH[1]}"
    printf "  │ %-60s │ %-32s │\n" "${ALL_GROUPS[$i]}" "$KEY_SHORT"
  done
  echo "  └──────────────────────────────────────────────────────────────┴──────────────────────────────────┘"
  echo ""
  exit 0
fi

echo "  KMS 미적용 로그 그룹 ${#UNENCRYPTED[@]}개 발견:"
echo ""
for i in "${!UNENCRYPTED[@]}"; do
  printf "  [%d] %s\n" $((i+1)) "${UNENCRYPTED[$i]}"
done
echo ""

# ─────────────────────────────────────────────────
# 2단계: 적용 대상 선택
# ─────────────────────────────────────────────────
echo "[2/4] 적용할 로그 그룹을 선택하세요."
echo "  - 전체 선택: Enter (기본값)"
echo "  - 개별 선택: 번호를 스페이스로 구분 (예: 1 3 5)"
echo "  - 취소: q"
echo ""
read -rp "  선택 > " SELECTION

if [[ "$SELECTION" == "q" || "$SELECTION" == "Q" ]]; then
  echo "  취소되었습니다."
  exit 0
fi

SELECTED=()
if [[ -z "$SELECTION" ]]; then
  SELECTED=("${UNENCRYPTED[@]}")
  echo "  → 전체 ${#SELECTED[@]}개 선택됨"
else
  for idx in $SELECTION; do
    if [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= ${#UNENCRYPTED[@]} )); then
      SELECTED+=("${UNENCRYPTED[$((idx-1))]}")
    else
      echo "  ⚠️  잘못된 번호 무시: $idx"
    fi
  done
fi

if [[ ${#SELECTED[@]} -eq 0 ]]; then
  echo "  선택된 로그 그룹이 없습니다. 종료합니다."
  exit 0
fi

echo ""
echo "  적용 대상:"
for lg in "${SELECTED[@]}"; do
  echo "    - $lg"
done
echo ""

# ─────────────────────────────────────────────────
# 3단계: KMS 키 선택 / 생성
# ─────────────────────────────────────────────────
echo "[3/4] 사용 가능한 KMS 키 조회 중..."
echo ""

CMK_ARNS=()
CMK_ALIASES=()
CMK_DESCS=()

while IFS=$'\t' read -r arn ali desc; do
  [[ -z "$arn" ]] && continue
  CMK_ARNS+=("$arn")
  CMK_ALIASES+=("${ali:-(없음)}")
  CMK_DESCS+=("${desc:-(설명 없음)}")
done < <(python3 -c "
import subprocess, json

keys_out = subprocess.run(
    ['aws', 'kms', 'list-keys', '--output', 'json'],
    capture_output=True, text=True
).stdout
keys = json.loads(keys_out).get('Keys', [])

aliases_out = subprocess.run(
    ['aws', 'kms', 'list-aliases', '--output', 'json'],
    capture_output=True, text=True
).stdout
alias_map = {}
for a in json.loads(aliases_out).get('Aliases', []):
    tid = a.get('TargetKeyId', '')
    if tid and not a['AliasName'].startswith('alias/aws/'):
        alias_map[tid] = a['AliasName']

for k in keys:
    kid = k['KeyId']
    arn = k['KeyArn']
    try:
        desc_out = subprocess.run(
            ['aws', 'kms', 'describe-key', '--key-id', kid, '--output', 'json'],
            capture_output=True, text=True
        ).stdout
        meta = json.loads(desc_out)['KeyMetadata']
        if meta['KeyState'] != 'Enabled' or meta['KeyManager'] == 'AWS':
            continue
        desc = meta.get('Description', '')
        alias = alias_map.get(kid, '')
        print(f'{arn}\t{alias}\t{desc}')
    except Exception:
        continue
" 2>/dev/null)

if [[ ${#CMK_ARNS[@]} -gt 0 ]]; then
  echo "  기존 고객 관리형 CMK ${#CMK_ARNS[@]}개 발견:"
  echo ""
  echo "  ┌─────┬────────────────────────────────────┬──────────────────────────────────────────┐"
  printf "  │ %3s │ %-34s │ %-40s │\n" "#" "Alias" "Description"
  echo "  ├─────┼────────────────────────────────────┼──────────────────────────────────────────┤"
  for i in "${!CMK_ARNS[@]}"; do
    KEY_SHORT="${CMK_ARNS[$i]}"
    [[ "$KEY_SHORT" =~ key/(.+)$ ]] && KEY_SHORT="${BASH_REMATCH[1]}"
    printf "  │ %3d │ %-34s │ %-40s │\n" $((i+1)) "${CMK_ALIASES[$i]}" "${CMK_DESCS[$i]:0:40}"
  done
  echo "  └─────┴────────────────────────────────────┴──────────────────────────────────────────┘"
  echo ""
  echo "  💡 기존 CMK 사용을 권장합니다 (KMS 키당 월 $1 비용 발생)"
  echo ""
  echo "  - 기존 키 선택: 번호 입력 (예: 1)"
  echo "  - 신규 CMK 생성: n"
  echo "  - 취소: q"
  echo ""
  read -rp "  선택 > " KMS_SELECTION

  if [[ "$KMS_SELECTION" == "q" || "$KMS_SELECTION" == "Q" ]]; then
    echo "  취소되었습니다."
    exit 0
  elif [[ "$KMS_SELECTION" == "n" || "$KMS_SELECTION" == "N" ]]; then
    KMS_KEY_ARN=""
  elif [[ "$KMS_SELECTION" =~ ^[0-9]+$ ]] && (( KMS_SELECTION >= 1 && KMS_SELECTION <= ${#CMK_ARNS[@]} )); then
    KMS_KEY_ARN="${CMK_ARNS[$((KMS_SELECTION-1))]}"
    echo ""
    echo "  ✅ 선택된 키: ${CMK_ALIASES[$((KMS_SELECTION-1))]} (${KMS_KEY_ARN##*/})"

    SELECTED_KEY_ID="${KMS_KEY_ARN##*/}"
    HAS_LOG_PERMISSION=$(aws kms get-key-policy --key-id "$SELECTED_KEY_ID" --policy-name default --output text 2>/dev/null | grep -c "logs\." || true)
    if [[ "$HAS_LOG_PERMISSION" -eq 0 ]]; then
      echo ""
      echo "  ⚠️  이 키에 CloudWatch Logs 서비스 권한이 없을 수 있습니다."
      echo "     적용 시 실패하면 KMS Key Policy에 logs.${REGION}.amazonaws.com 권한을 추가하세요."
    fi
  else
    echo "  ⚠️  잘못된 입력. 종료합니다."
    exit 1
  fi
else
  echo "  기존 고객 관리형 CMK가 없습니다."
  KMS_KEY_ARN=""
fi

if [[ -z "$KMS_KEY_ARN" ]]; then
  echo ""
  echo "  신규 CMK를 생성합니다... (Alias: $KMS_ALIAS)"

  KEY_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Id": "CloudWatchLogsKMSPolicy",
  "Statement": [
    {
      "Sid": "EnableRootAccountFullAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ACCOUNT_ID}:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowCloudWatchLogsUsage",
      "Effect": "Allow",
      "Principal": {
        "Service": "logs.${REGION}.amazonaws.com"
      },
      "Action": [
        "kms:Encrypt*",
        "kms:Decrypt*",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:Describe*"
      ],
      "Resource": "*",
      "Condition": {
        "ArnLike": {
          "kms:EncryptionContext:aws:logs:arn": "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:*"
        }
      }
    }
  ]
}
EOF
  )

  KMS_KEY_ID=$(aws kms create-key \
    --description "CMK for CloudWatch Logs encryption" \
    --policy "$KEY_POLICY" \
    --query 'KeyMetadata.KeyId' \
    --output text)

  ALIAS_EXISTS=$(aws kms list-aliases --query "Aliases[?AliasName==\`$KMS_ALIAS\`].AliasName | [0]" --output text 2>/dev/null || echo "None")
  if [[ "$ALIAS_EXISTS" == "None" || -z "$ALIAS_EXISTS" ]]; then
    aws kms create-alias \
      --alias-name "$KMS_ALIAS" \
      --target-key-id "$KMS_KEY_ID"
  fi

  KMS_KEY_ARN=$(aws kms describe-key --key-id "$KMS_KEY_ID" \
    --query 'KeyMetadata.Arn' --output text)

  echo "  ✅ 신규 KMS 키 생성 완료: $KMS_KEY_ARN"
fi

echo ""

# ─────────────────────────────────────────────────
# 4단계: 선택된 로그 그룹에 KMS 적용
# ─────────────────────────────────────────────────
echo "[4/4] KMS 키 적용 시작..."
echo "  대상 KMS ARN: $KMS_KEY_ARN"
echo ""

SUCCESS=0
FAIL=0
SKIP=0
FAILED_GROUPS=()

for lg in "${SELECTED[@]}"; do
  printf "  [%s] %-55s ... " "$(date '+%H:%M:%S')" "$lg"

  CURRENT_KMS=$(aws logs describe-log-groups \
    --log-group-name-prefix "$lg" \
    --query "logGroups[?logGroupName==\`$lg\`].kmsKeyId | [0]" \
    --output text 2>/dev/null || echo "None")

  if [[ "$CURRENT_KMS" != "None" && -n "$CURRENT_KMS" ]]; then
    echo "⏭️  SKIP (이미 적용됨: ${CURRENT_KMS##*/})"
    ((SKIP++)) || true
    continue
  fi

  START_TS=$(date +%s%N)
  ERR_MSG=$(aws logs associate-kms-key \
    --region "$REGION" \
    --log-group-name "$lg" \
    --kms-key-id "$KMS_KEY_ARN" 2>&1)
  RC=$?
  END_TS=$(date +%s%N)
  ELAPSED_MS=$(( (END_TS - START_TS) / 1000000 ))

  if [[ $RC -eq 0 ]]; then
    echo "✅ (${ELAPSED_MS}ms)"
    ((SUCCESS++)) || true
  else
    echo "❌ (${ELAPSED_MS}ms)"
    echo "        ↳ 에러: $ERR_MSG"
    FAILED_GROUPS+=("$lg")
    ((FAIL++)) || true
  fi
done

echo ""
echo "=============================================="
echo " 완료! 성공: ${SUCCESS}개 / 스킵: ${SKIP}개 / 실패: ${FAIL}개"
echo "=============================================="

if [[ ${#FAILED_GROUPS[@]} -gt 0 ]]; then
  echo ""
  echo " ⚠️  실패한 로그 그룹:"
  for fg in "${FAILED_GROUPS[@]}"; do
    echo "    - $fg"
  done
fi
echo ""

echo "[결과 확인] 적용된 로그 그룹 KMS 현황:"
echo ""
VERIFY_OK=0
VERIFY_FAIL=0

for lg in "${SELECTED[@]}"; do
  KMS_RESULT=$(aws logs describe-log-groups \
    --log-group-name-prefix "$lg" \
    --query "logGroups[?logGroupName==\`$lg\`].kmsKeyId | [0]" \
    --output text 2>/dev/null || echo "조회실패")

  if [[ "$KMS_RESULT" != "None" && "$KMS_RESULT" != "조회실패" && -n "$KMS_RESULT" ]]; then
    printf "  ✅ %-55s → %s\n" "$lg" "$KMS_RESULT"
    ((VERIFY_OK++)) || true
  else
    printf "  ❌ %-55s → %s\n" "$lg" "${KMS_RESULT:-미적용}"
    ((VERIFY_FAIL++)) || true
  fi
done

echo ""
echo "  검증 결과: KMS 적용 확인 ${VERIFY_OK}개 / 미적용 ${VERIFY_FAIL}개"
echo ""
echo "Done."