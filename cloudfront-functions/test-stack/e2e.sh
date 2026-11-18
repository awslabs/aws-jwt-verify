#!/usr/bin/env bash
# End-to-end test of the CloudFront Functions JWT verifier against the deployed test stack.
# Needs: outputs.json from `npm run deploy`, the AWS CLI with credentials for the stack's
# account, curl and node. Tokens are never printed past their first 8 characters.
set -euo pipefail
cd "$(dirname "$0")"

STACK=aws-jwt-verify-cloudfront-functions
out() { node -e "process.stdout.write(require('./outputs.json')['$STACK']['$1'])"; }
REGION=$(out Region)
POOL=$(out UserPoolId)
CLIENT=$(out ClientId)
OTHER_CLIENT=$(out OtherClientId)
USERNAME=$(out TestUserName)
SECRET=$(out TestUserPasswordSecretName)
KVS=$(out KeyValueStoreArn)
BASE="https://$(out DistributionDomainName)"
ISSUER="https://cognito-idp.$REGION.amazonaws.com/$POOL"
PREFIX="jwk:"

PASS=0
FAIL=0
# js <expression of v>: evaluates it on the JSON read from stdin
js() { node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const v=JSON.parse(d);const r=($1);process.stdout.write(typeof r==='string'?r:JSON.stringify(r))})"; }
json() { js "v$1"; }
short() { printf '%s…' "${1:0:8}"; }

# --- Tokens ------------------------------------------------------------------------
PASSWORD=$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "$SECRET" --query SecretString --output text)
sign_in() {
  aws cognito-idp admin-initiate-auth --region "$REGION" --user-pool-id "$POOL" --client-id "$1" \
    --auth-flow ADMIN_USER_PASSWORD_AUTH \
    --auth-parameters "USERNAME=$USERNAME,PASSWORD=$PASSWORD" \
    --query "AuthenticationResult.[AccessToken,IdToken]" --output text
}
read -r ACCESS ID < <(sign_in "$CLIENT")
read -r OTHER_ACCESS _ < <(sign_in "$OTHER_CLIENT")
unset PASSWORD
SUB=$(echo "$ACCESS" | cut -d. -f2 | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>process.stdout.write(JSON.parse(Buffer.from(d.trim(),'base64url')).sub))")
echo "signed in: access $(short "$ACCESS"), id $(short "$ID"), other client $(short "$OTHER_ACCESS")"

# Forged: the real token with another sub, and the original signature
H=$(echo "$ACCESS" | cut -d. -f1)
S=$(echo "$ACCESS" | cut -d. -f3)
P=$(echo "$ACCESS" | cut -d. -f2 | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const p=JSON.parse(Buffer.from(d.trim(),'base64url'));p.sub='admin';process.stdout.write(Buffer.from(JSON.stringify(p)).toString('base64url'))})")
FORGED="$H.$P.$S"

TEST=$(npx ts-node e2e-tokens.ts "$ISSUER" "$CLIENT")
tok() { echo "$TEST" | json ".tokens.$1"; }
test_kids() { echo "$TEST" | js "Object.keys(v.jwks).join(' ')"; }

# --- KVS -----------------------------------------------------------------------------
etag() { aws cloudfront-keyvaluestore describe-key-value-store --kvs-arn "$KVS" --query ETag --output text; }
kvs_put() { aws cloudfront-keyvaluestore put-key --kvs-arn "$KVS" --if-match "$(etag)" --key "$1" --value "$2" >/dev/null; }
kvs_del() { aws cloudfront-keyvaluestore delete-key --kvs-arn "$KVS" --if-match "$(etag)" --key "$1" >/dev/null 2>&1 || true; }
kvs_keys() { aws cloudfront-keyvaluestore list-keys --kvs-arn "$KVS" --query "Items[].Key" --output text | tr '\t' '\n' | grep -v '^None$' || true; }
seed_cognito_jwks() {
  local jwks
  jwks=$(curl -sf "$ISSUER/.well-known/jwks.json")
  for kid in $(echo "$jwks" | js "v.keys.map(k=>k.kid).join(' ')"); do
    kvs_put "$PREFIX$kid" "$(echo "$jwks" | json ".keys.find(k=>k.kid==='$kid')")"
  done
}

# --- Checks --------------------------------------------------------------------------
# check <name> <path> <token or ""> <expected status> <expected x-jwt-error or jwks source> [extra curl args]
LAST_BODY=""
request() {
  local path=$1 token=$2
  shift 2
  local args=(-s -o /tmp/e2e-body.$$ -D /tmp/e2e-headers.$$ -w '%{http_code}' "$@")
  [ -n "$token" ] && args+=(-H "authorization: Bearer $token")
  curl "${args[@]}" "$BASE$path"
}
check() {
  local name=$1 path=$2 token=$3 want_status=$4 want=$5
  shift 5
  local status got
  status=$(request "$path" "$token" "$@")
  LAST_BODY=$(cat /tmp/e2e-body.$$)
  if [ "$status" = 200 ]; then
    got=$(echo "$LAST_BODY" | json ".jwks")
  else
    got=$(grep -i '^x-jwt-error:' /tmp/e2e-headers.$$ | cut -d' ' -f2- | tr -d '\r' || true)
  fi
  if [ "$status" = "$want_status" ] && [[ "$got" == $want* ]]; then
    PASS=$((PASS + 1))
    printf 'PASS  %-58s %s %s\n' "$name" "$status" "$got"
  else
    FAIL=$((FAIL + 1))
    printf 'FAIL  %-58s %s %s (want %s %s)\n' "$name" "$status" "$got" "$want_status" "$want"
  fi
}
# Retries a check until the KVS change has propagated (up to ~60 s)
eventually() {
  local i
  for i in $(seq 1 12); do
    local before=$FAIL
    check "$@" >/tmp/e2e-line.$$
    if [ "$FAIL" = "$before" ]; then cat /tmp/e2e-line.$$; return; fi
    FAIL=$before
    sleep 5
  done
  check "$@"
}
trap 'rm -f /tmp/e2e-*.$$' EXIT

echo "distribution: $BASE"
echo "--- the KVS holds only this run's test keys: Cognito's kid is unknown to it ---"
for k in $(kvs_keys); do kvs_del "$k"; done
for kid in $(test_kids); do
  kvs_put "$PREFIX$kid" "$(echo "$TEST" | json ".jwks['$kid']")"
done
eventually "test RS256 key in the KVS (propagated)" / "$(tok rs256)" 200 kvs
eventually "valid access token, kid not in KVS: JWKS refetched" / "$ACCESS" 200 fetch
[ "$(echo "$LAST_BODY" | json ".sub")" = "$SUB" ] && echo "      origin got x-jwt-sub of the signed-in user" || { echo "FAIL  wrong sub at origin"; FAIL=$((FAIL + 1)); }

echo "--- Cognito JWKS seeded into the KVS ---"
seed_cognito_jwks
eventually "valid access token, JWK from KVS (no call)" / "$ACCESS" 200 kvs
check "ES256 token (test key)" / "$(tok es256)" 200 kvs
check "spoofed x-jwt-sub from the viewer is dropped" / "$ACCESS" 200 kvs -H "x-jwt-sub: admin"
[ "$(echo "$LAST_BODY" | json ".sub")" = "$SUB" ] && echo "      origin got the token's sub, not the spoofed one" || { echo "FAIL  spoofed sub reached origin"; FAIL=$((FAIL + 1)); }

echo "--- invalid tokens: 401 ---"
check "no token" / "" 401 JwtParseError
check "malformed token" / "not-a-jwt" 401 JwtParseError
check "expired (test key, valid signature)" / "$(tok expired)" 401 JwtExpiredError
check "wrong client id (other app client)" / "$OTHER_ACCESS" 401 CognitoJwtInvalidClientIdError
check "wrong token_use (ID token)" / "$ID" 401 CognitoJwtInvalidTokenUseError
check "forged signature (payload changed)" / "$FORGED" 401 JwtInvalidSignatureError
check "unknown kid: refetch, still unknown" / "$(tok unknownKid)" 401 KidNotFoundInJwksError

echo "--- issuer cannot be reached: fail closed ---"
check "issuer unreachable (DNS)" /unreachable/x "$ACCESS" 503 "FetchError: JWKS fetch failed"
check "issuer does not answer (black-holed port)" /slow/x "$ACCESS" 503 "FetchError: JWKS fetch failed"

echo "--- protected origin is not reachable directly ---"
FN_URL=$(aws lambda list-function-url-configs --region "$REGION" --function-name "$(aws cloudformation describe-stack-resources --region "$REGION" --stack-name "$STACK" --query "StackResources[?ResourceType=='AWS::Lambda::Function' && starts_with(LogicalResourceId, 'EchoFn')].PhysicalResourceId" --output text)" --query "FunctionUrlConfigs[0].FunctionUrl" --output text)
DIRECT=$(curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer $ACCESS" "$FN_URL")
if [ "$DIRECT" = 403 ]; then PASS=$((PASS + 1)); echo "PASS  direct function URL call refused                              403"; else FAIL=$((FAIL + 1)); echo "FAIL  direct function URL call $DIRECT"; fi

echo "--- cleanup: remove this run's test keys, keep the Cognito JWKS ---"
for kid in $(test_kids); do
  kvs_del "$PREFIX$kid"
done
echo "KVS keys now: $(kvs_keys | tr '\n' ' ')"

echo "passed $PASS, failed $FAIL"
[ "$FAIL" = 0 ]
