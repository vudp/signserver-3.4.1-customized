## Get started

You can find the original project version from https://www.signserver.org/
This project is adapted for my usage.

## Requirements

* Java 1.7.x
* JBoss 5
* MySQL 5.7.x
* Ant 1.9.1

## Set your variables environment
<pre>
JAVA_HOME=/usr/java/latest
export JAVA_HOME
PATH=$JAVA_HOME/bin:$PATH
export PATH

JBOSS_HOME=/opt/CAG360/EnterprisePlatform-5.2.0/jboss-eap-5.2/jboss-as
export JBOSS_HOME

ANT_HOME=/opt/CAG360/apache-ant-1.9.1
export ANT_HOME

PATH=$ANT_HOME/bin:$PATH
export PATH

SIGNSERVER_HOME=/opt/CAG360/signserver-3.4.1
export SIGNSERVER_HOME

export ANT_OPTS="-Xmx512m -XX:MaxPermSize=512m"
export JAVA_OPTS="-Xmx6G -Xms2G -XX:PermSize=512m -XX:MaxPermSize=1024m -server"
export SIGNSERVER_NODEID=localhost
export APPSRV_HOME=/opt/CAG360/EnterprisePlatform-5.2.0/jboss-eap-5.2/jboss-as
</pre>

## Build & Deploy
<pre>
  cd $SIGNSERVER_HOME
  bin/ant clean
  bin/ant build
  bin/ant deploy
</pre>
## Run
Start your JBoss service
<pre>
  service jboss start
</pre>
