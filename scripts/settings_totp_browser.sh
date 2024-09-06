#!/bin/sh

IFS='
'

publicEndpoint=http://localhost:4433
adminEndpoint=http://localhost:4434

echo "------------- [create settings flow (method: totp)] -------------"
responseCreateSettingsFlow=$(curl -v -s -X GET \
  -c .session_cookie -b .session_cookie \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  $publicEndpoint/self-service/settings/browser)
echo $responseCreateSettingsFlow | jq 

actionUrl=$(echo $responseCreateSettingsFlow | jq -r '.ui.action')
csrfToken=$(echo $responseCreateSettingsFlow | jq -r '.ui.nodes[] | select(.attributes.name=="csrf_token") | .attributes.value') 

echo "\n\n\n------------- [complete settings flow (method: totp)] -------------"
responseCompleteSettingsFlow=$(curl -v -s -X POST \
  -c .session_cookie -b .session_cookie \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"csrf_token": "'$csrfToken'", "method": "totp"}' \
  "$actionUrl")
echo $responseCompleteSettingsFlow | jq 


# echo "\n\n\n------------- [complete settings flow (method: totp)] -------------"
# responseCompleteSettingsFlow=$(curl -v -s -X POST \
#   -c .session_cookie -b .session_cookie \
#   -H "Accept: application/json" \
#   -H "Content-Type: application/json" \
#   -d '{"csrf_token": "'$csrfToken'", "method": "totp", "totp_confirm": true}' \
#   "$actionUrl")
# echo $responseCompleteSettingsFlow | jq 

