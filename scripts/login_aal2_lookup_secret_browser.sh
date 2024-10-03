#!/bin/sh

IFS='
'

email=$1
if [ -z "$email" ]; then
  email=1@local
fi

password=$2
if [ -z "$password" ]; then
  password=overwatch2023
fi

lookup_secret=tns9wjbr

publicEndpoint=http://localhost:4433
adminEndpoint=http://localhost:4434

echo "------------- [create login flow] -------------"
responseCreateLoginFlow=$(curl -v -s -X GET \
  -c .session_cookie -b .session_cookie \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "$publicEndpoint/self-service/login/browser?refresh=true&aal=aal2")
echo $responseCreateLoginFlow | jq 

actionUrlSubmitLogin=$(echo $responseCreateLoginFlow | jq -r '.ui.action')
csrfToken=$(echo $responseCreateLoginFlow | jq -r '.ui.nodes[] | select(.attributes.name=="csrf_token") | .attributes.value') 

echo "\n\n\n------------- [submit login flow] -------------"
responseSubmitLoginFlow=$(curl -v -s -X POST \
  -c .session_cookie -b .session_cookie \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"csrf_token": "'$csrfToken'", "method": "lookup_secret", "lookup_secret": "'$lookup_secret'"}' \
  "$actionUrlSubmitLogin")
echo $responseSubmitLoginFlow | jq 

