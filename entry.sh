#!/bin/sh
if [ -z "${AWS_LAMBDA_RUNTIME_API}" ]; then
  echo "if match"
  exec /usr/bin/aws-lambda-rie "$@"
else
  echo "else branch"
  exec "$@"
fi