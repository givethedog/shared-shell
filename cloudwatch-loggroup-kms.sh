
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

UNENCRYPTED=()
while IFS= read -r lg; do
  [[ -n "$lg" ]] && UNENCRYPTED+=("$lg")
done < <(aws logs describe-log-groups \
  --query 'logGroups[?!kmsKeyId].logGroupName' \
  --output text | tr '\t' '\n')

if [[ ${#UNENCRYPTED[@]} -eq 0 ]]; then
  echo "  ✅ 모든 로그 그룹에 KMS가 적용되어 있습니다. 종료합니다."
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
# 3단계: KMS 키 확인 / 생성
# ─────────────────────────────────────────────────
echo "[3/4] KMS 키 확인 중... (Alias: $KMS_ALIAS)"

KMS_KEY_ARN=$(aws kms describe-key --key-id "$KMS_ALIAS" \
  --query 'KeyMetadata.Arn' --output text 2>/dev/null || true)

if [[ -n "$KMS_KEY_ARN" && "$KMS_KEY_ARN" != "None" ]]; then
  echo "  ✅ 기존 KMS 키 발견: $KMS_KEY_ARN"
else
  echo "  KMS 키가 존재하지 않습니다. 신규 CMK를 생성합니다..."

  # CloudWatch Logs 서비스가 사용할 수 있는 Key Policy
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

  aws kms create-alias \
    --alias-name "$KMS_ALIAS" \
    --target-key-id "$KMS_KEY_ID"

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
    ((SKIP++))
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
    ((SUCCESS++))
  else
    echo "❌ (${ELAPSED_MS}ms)"
    echo "        ↳ 에러: $ERR_MSG"
    FAILED_GROUPS+=("$lg")
    ((FAIL++))
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
    ((VERIFY_OK++))
  else
    printf "  ❌ %-55s → %s\n" "$lg" "${KMS_RESULT:-미적용}"
    ((VERIFY_FAIL++))
  fi
done

echo ""
echo "  검증 결과: KMS 적용 확인 ${VERIFY_OK}개 / 미적용 ${VERIFY_FAIL}개"
echo ""
echo "Done."