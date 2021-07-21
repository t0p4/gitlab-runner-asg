#!/usr/bin/env bash

GITLABRunnerExecutor='docker'

MYIP="$(curl http://169.254.169.254/latest/meta-data/local-ipv4)"
MYACCOUNTID="$(curl http://169.254.169.254/latest/dynamic/instance-identity/document|grep accountId| awk '{print $3}'|sed  's/"//g'|sed 's/,//g')"
RunnerName="$MYINSTANCEID-in-$MYACCOUNTID-at-$AWS_REGION"

function logit() {
  LOGSTRING="$(date +"%_b %e %H:%M:%S") $(hostname) USERDATA_SCRIPT: $1"
  #For CloudFormation, if you already collect /var/log/cloud-init-output.log or /var/log/messsages (non amazon linux), then you could mute the next logging line
  echo "$LOGSTRING" >> /var/log/messages
}                     

logit "Preflight checks for required endpoints..."
urlportpairlist="$(echo $GITLABRunnerInstanceURL | cut -d'/' -f3 | cut -d':' -f1)=443 gitlab-runner-downloads.s3.amazonaws.com=443"
failurecount=0
for urlportpair in $urlportpairlist; do
  set -- $(echo $urlportpair | tr '=' ' ') ; url=$1 ; port=$2
  logit "TCP Test of $url on $port"
  timeout 3 bash -c "cat < /dev/null > /dev/tcp/$url/$port"
  if [ "$?" -ne 0 ]; then
    logit "  Connection to $url on port $port failed"
    ((failurecount++))
  else
    logit "  Connection to $url on port $port succeeded"
  fi
done

if [ $failurecount -gt 0 ]; then
 logit "$failurecount tcp connect tests failed. Please check all networking configuration for problems."
  if [ -f /opt/aws/bin/cfn-signal ]; then 
    /opt/aws/bin/cfn-signal --success false --stack ${AWS::StackName} --resource InstanceASG --region $AWS_REGION --reason "Cant connect to GitLab or other endpoints"
  fi
  exit $failurecount
fi

#Detect package manager
if [[ -n "$(command -v yum)" ]] ; then
  PKGMGR='yum'
elif [[ -n "$(command -v apt-get)" ]] ; then
  PKGMGR='apt-get'
fi

set -ex
if [[ -z "$(command -v docker)" ]] ; then
  echo "Docker not present, installing..."
  amazon-linux-extras install docker
  usermod -a -G docker ec2-user
  systemctl enable docker.service
  systemctl start docker.service
fi

RunnerCompleteTagList="$RunnerOSTags,glexecutor-$GITLABRunnerExecutor,${OSInstanceLinuxArch,,}"

if [[ -n "${GITLABRunnerTagList}" ]]; then RunnerCompleteTagList="$RunnerCompleteTagList,${GITLABRunnerTagList,,}"; fi
if [[ -n "${COMPUTETYPE}" ]]; then RunnerCompleteTagList="$RunnerCompleteTagList,computetype-${COMPUTETYPE,,}"; fi

# Installing and configuring Gitlab Runner
if [ ! -d $RunnerInstallRoot ]; then mkdir -p $RunnerInstallRoot; fi

curl https://gitlab-runner-downloads.s3.amazonaws.com/${GITLABRunnerVersion,,}/binaries/gitlab-runner-linux-${OSInstanceLinuxArch} --output $RunnerInstallRoot/gitlab-runner
chmod +x $RunnerInstallRoot/gitlab-runner
if ! id -u "gitlab-runner" >/dev/null 2>&1; then
  useradd --comment 'GitLab Runner' --create-home gitlab-runner --shell /bin/bash
fi
$RunnerInstallRoot/gitlab-runner install --user="gitlab-runner" --working-directory="/gitlab-runner"
echo -e "\nRunning scripts as '$(whoami)'\n\n"

for RunnerRegToken in ${GITLABRunnerRegTokenList//;/ }
do
  $RunnerInstallRoot/gitlab-runner register \
    --non-interactive \
    --name $RunnerName \
    --config $RunnerConfigToml \
    --url "$GITLABRunnerInstanceURL" \
    --registration-token "$RunnerRegToken" \
    --request-concurrency "$GITLABRunnerConcurrentJobs" \
    --executor "$GITLABRunnerExecutor" \
    --run-untagged="true" \
    --tag-list "$RunnerCompleteTagList" \
    --locked="false" \
    --cache-type "s3" \
    --cache-path "/" \
    --cache-shared="true" \
    --cache-s3-server-address "s3.amazonaws.com" \
    --cache-s3-bucket-name $GITLABRunnerS3CacheBucket \
    --cache-s3-bucket-location $AWS_REGION \
    --docker-volumes "/var/run/docker.sock:/var/run/docker.sock" \
    --docker-image "docker:latest" \
    --docker-privileged \
    --docker-tlsverify="false" \
    --docker-disable-cache="false" \
    --docker-shm-size 0
done

$RunnerInstallRoot/gitlab-runner start

aws ec2 create-tags --region $AWS_REGION --resources $MYINSTANCEID --tags Key=GitLabRunnerName,Value="$RunnerName" Key=GitLabURL,Value="$GITLABRunnerInstanceURL" Key=GitLabRunnerTags,Value="$(echo $RunnerCompleteTagList | sed 's/,/\\\,/g')"

#$RunnerInstallRoot/gitlab-runner unregister --all-runners

#Escape $ for variables that should wait until script runtime to be expanded. 
#Non-especaped $ will result in variable expansion DURING script writing which is used on purpose by this heredoc.
#This approach for termination hook is much simpler than those involving SNS or CloudWatch, but when deployed 
# on many instances it can result in a lot of ASG Describe API calls (which may be rate limited).

if [ ! -z "$NAMEOFASG" ] && [ "$ASGSelfMonitorTerminationInterval" != "Disabled" ] && [ "$WaitingForReboot" != "true" ]; then
  logit "Setting up termination monitoring because 5ASGSelfMonitorTerminationInterval is set to $ASGSelfMonitorTerminationInterval"
  SCRIPTNAME=/etc/cron.d/MonitorTerminationHook.sh
  SCRIPTFOLDER=$(dirname $SCRIPTNAME)
  SCRIPTBASENAME=$(basename $SCRIPTNAME)
  
  #Heredoc script
  cat << EndOfScript > $SCRIPTNAME
    function logit() {
      LOGSTRING="\$(date +'%_b %e %H:%M:%S') \$(hostname) TERMINATIONMON_SCRIPT: \$1"
      echo "\$LOGSTRING"
      echo "\$LOGSTRING" >> /var/log/messages
    }
    #These are resolved at script creation time to reduce api calls when this script runs every minute on instances.

    if [[ "\$(aws autoscaling describe-auto-scaling-instances --instance-ids $MYINSTANCEID --region $AWS_REGION | jq --raw-output '.AutoScalingInstances[0] .LifecycleState')" == *"Terminating"* ]]; then
      logit "This instance ($MYINSTANCEID) is being terminated, perform cleanup..."

      if [ "${COMPUTETYPE,,}" != "spot" ]; then
        logit "Instance is not spot compute, draining running jobs..."
        $RunnerInstallRoot/gitlab-runner stop
      else
        logit "Instance is spot compute, deregistering runner immediately without draining running jobs..."
      fi
      $RunnerInstallRoot/gitlab-runner unregister --all-runners

      #### PUT YOUR CLEANUP CODE HERE, DECIDE IF CLEANUP CODE SHOULD ERROR OUT OR SILENTLY FAIL (best effort cleanup)

      aws autoscaling complete-lifecycle-action --region $AWS_REGION --lifecycle-action-result CONTINUE --instance-id $MYINSTANCEID --lifecycle-hook-name instance-terminating --auto-scaling-group-name $NAMEOFASG
      logit "This instance ($MYINSTANCEID) is ready for termination"
      logit "Lifecycle CONTINUE was sent to termination hook in ASG: $NAMEOFASG for this instance ($MYINSTANCEID)."
    fi
EndOfScript
fi

echo "Settings up CloudWatch Metrics to Enable Scaling on Memory Utilization"
yum install amazon-cloudwatch-agent
systemctl stop amazon-cloudwatch-agent
cat << 'EndOfCWMetricsConfig' > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
{
  "agent": {
    "metrics_collection_interval": 30,
    "run_as_user": "root"
  },
  "metrics": {
    "aggregation_dimensions" : [["AutoScalingGroupName"], ["InstanceId"], ["InstanceType"], ["InstanceId","InstanceType"]],
    "append_dimensions": {
      "AutoScalingGroupName": "${aws:AutoScalingGroupName}",
      "ImageId": "${aws:ImageId}",
      "InstanceId": "${aws:InstanceId}",
      "InstanceType": "${aws:InstanceType}"
    },
    "metrics_collected": {
      "cpu": {
        "measurement": [
          "cpu_usage_idle",
          "cpu_usage_iowait",
          "cpu_usage_user",
          "cpu_usage_system"
        ],
        "metrics_collection_interval": 30,
        "totalcpu": false
      },
      "disk": {
        "measurement": [
          "used_percent",
          "inodes_free"
        ],
        "metrics_collection_interval": 30,
        "resources": [
                "*"
        ]
      },
      "diskio": {
        "measurement": [
          "io_time",
          "write_bytes",
          "read_bytes",
          "writes",
          "reads"
        ],
        "metrics_collection_interval": 30,
        "resources": [
          "*"
        ]
      },
      "mem": {
        "measurement": [
          "mem_used_percent"
        ],
        "metrics_collection_interval": 30
      },
      "netstat": {
        "measurement": [
          "tcp_established",
          "tcp_time_wait"
        ],
        "metrics_collection_interval": 30
      },
      "swap": {
        "measurement": [
          "swap_used_percent"
        ],
        "metrics_collection_interval": 30
      }
    }
  }
}
EndOfCWMetricsConfig
systemctl enable amazon-cloudwatch-agent
systemctl restart amazon-cloudwatch-agent
#Debugging:
#Check if running: sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a status
#config: cat /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
#log file: tail /opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log -f
#wizard saves: /opt/aws/amazon-cloudwatch-agent/bin/config.json
#amazon-linux-extras install -y epel; yum install -y stress-ng
#stress-ng --vm 1 --vm-bytes 75% --vm-method all --verify -t 10m -v
#stress-ng --vm-hang 2 --vm-keep --verify --timeout 600 --verbose --vm 2 --vm-bytes $(awk '/MemTotal/{printf "%d\n", $2;}' < /proc/meminfo)k
# --vm-method all 
#stress-ng --vm-hang 2 --vm-keep --verify --timeout 600 --verbose --vm 2 --vm-bytes $(awk '/MemAvailable/{printf "%d\n", $2 * 0.9;}' < /proc/meminfo)k


#90% of available memory: $(awk '/MemAvailable/{printf "%d\n", $2 * 0.9;}' < /proc/meminfo)k
#100% of total memory: $(awk '/MemTotal/{printf "%d\n", $2;}' < /proc/meminfo)k
# cpus * 2: $(awk '/cpu cores/{printf "%d\n", $4 * 2;}' < /proc/cpuinfo)
