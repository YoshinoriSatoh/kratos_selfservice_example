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

publicEndpoint=http://localhost:4433
adminEndpoint=http://localhost:4434

echo "------------- [create registration flow] -------------"
responseCreateRegistrationFlow=$(curl -v -s -X GET \
  -c .session_cookie \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  $publicEndpoint/self-service/registration/browser)
echo $responseCreateRegistrationFlow | jq 

actionUrl=$(echo $responseCreateRegistrationFlow | jq -r '.ui.action')
csrfToken=$(echo $responseCreateRegistrationFlow | jq -r '.ui.nodes[] | select(.attributes.name=="csrf_token") | .attributes.value') 

echo "\n\n\n------------- [update registration flow] -------------"
responseUpdateRegistrationFlow=$(curl -v -s -X POST \
  -c .session_cookie -b .session_cookie \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"csrf_token": "'$csrfToken'", "traits.email": "'$email'", "password": "'$password'", "method": "password", "traits.firstname": "firstname", "traits.lastname": "lastname", "traits.nickname": "nickname"}' \
  "$actionUrl") 
echo $responseUpdateRegistrationFlow | jq

read -p "please input code emailed to you: " code

verificationFlowId=$(echo $responseUpdateRegistrationFlow | jq -r -c '.continue_with[] | select(.action=="show_verification_ui") | .flow.id')
echo $verificationFlowId 

echo "\n\n\n------------- [get verification flow] -------------"
responseGetVerificationFlow=$(curl -v -s -X GET \
  -b .session_cookie -c .session_cookie \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "$publicEndpoint/self-service/verification/flows?id=$verificationFlowId")
echo $responseGetVerificationFlow | jq 

csrfToken=$(echo $responseGetVerificationFlow | jq -r '.ui.nodes[] | select(.attributes.name=="csrf_token") | .attributes.value') 

echo "\n\n\n------------- [complete verification flow (send verification flow)] -------------"
responseUpdateVerificationFlow=$(curl -v -s -X POST \
  -c .session_cookie -b .session_cookie \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"csrf_token": "'$csrfToken'", "code": "'$code'", "method": "code"}' \
  "$publicEndpoint/self-service/verification?flow=$verificationFlowId")
echo $responseUpdateVerificationFlow | jq 


