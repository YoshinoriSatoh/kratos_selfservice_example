#!/bin/sh

IFS='
'

publicEndpoint=http://localhost:4433
adminEndpoint=http://localhost:4434

echo "------------- [create settings flow (method: lookup_secret)] -------------"
responseCreateSettingsFlow=$(curl -v -s -X GET \
  -c .session_cookie -b .session_cookie \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  $publicEndpoint/self-service/settings/browser)
echo $responseCreateSettingsFlow | jq 

actionUrl=$(echo $responseCreateSettingsFlow | jq -r '.ui.action')
csrfToken=$(echo $responseCreateSettingsFlow | jq -r '.ui.nodes[] | select(.attributes.name=="csrf_token") | .attributes.value') 

echo "\n\n\n------------- [complete settings flow (method: lookup_secret)] -------------"
responseCompleteSettingsFlow=$(curl -v -s -X POST \
  -c .session_cookie -b .session_cookie \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"csrf_token": "'$csrfToken'", "method": "lookup_secret", "lookup_secret_regenerate": true}' \
  "$actionUrl")
echo $responseCompleteSettingsFlow | jq 


echo "\n\n\n------------- [complete settings flow (method: lookup_secret)] -------------"
responseCompleteSettingsFlow=$(curl -v -s -X POST \
  -c .session_cookie -b .session_cookie \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"csrf_token": "'$csrfToken'", "method": "lookup_secret", "lookup_secret_confirm": true}' \
  "$actionUrl")
echo $responseCompleteSettingsFlow | jq 

