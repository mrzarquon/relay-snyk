docker build -t snyk-trigger-issues .
docker tag snyk-trigger-issues mrzarquon/snyk-trigger-issues:latest
docker push mrzarquon/snyk-trigger-issues:latest