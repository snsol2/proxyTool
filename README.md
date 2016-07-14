# 
# haproxy 환경 구성 및 상태확인 Tool
#
1. 환경 구성
#
  1.1 기본 정보
      - haproxy는 이중화 시스템으로 구성한다.
	    +- vrrp protocol을 이용하여 haproxy 서비스 IP를 이중화 한다.
	  - vrrp protocol은 keepalived 데몬을 이용한다.
  1.2 설치 시스템 정보
      - OS는 우분투를 사용한다.
	  - 기본 설정은 ONOS OpenStackNetworking App. REST API Proxy 처리를 제공한다. 
	  - 기본 설정은 ONOS Instance를 3개로 구성한다.
  1.3 환경 구성 파일
     - Tool의 환경 구성파일은 config/haproxy.json 이다.
	   +- haproxy information 
	      *- haproxy1, haproxy2 시스템 ssh 접속 정보 및 root passwd 정보
	   +- haproxy, keepalived pkg info (file name : xxxxxxxxx.tar.gz)
	      *- haproxy, keepalived 패키지 version 정보
		  *- 패키지 파일은 정보.tar.gz 로 구성
	   +- scp source path
	      *- 패키지 설치 시 환경 정보와 설치 패키지 파일 위칙 정보
	   +- keepalive information
	      *- vrrp 서비스 정보
   1.4 config 디렉토리 파일 정보
	 - haproxy.json   
	 - hosts.haproxy1 : haproxy1 시스템에 설치할 /etc/hosts 파일
	 - hosts.haproxy2 : haproxy2 시스템에 설치할 /etc/hosts 파일
	 - keepalived_haproxy1.conf : haproxy1 시스템에 설치할 /etc/keepalived/keepalived.conf 파일
	                              vrrp 서비스 설정
	 - keepalived_haproxy2.conf : haproxy2 시스템에 설치할 /etc/keepalived/keepalived.conf 파일
	                              vrrp 서비스 설정
   1.5 common 디렉토리 파일 정보
	 - haproxy-1.6.5.tar.gz : haproxy 패키지 파일
	 - haproxy.cfg : haproxy 환경 구성 파일, haproxy1/haproxy2 시스템에 설치할 /etc/haproxy/haproxy.cfg 파일 
	 - haproxy_upstart_script : haproxy 기동 스크립트, haproxy1/haproxy2 시스템에 설치할/etc/init.d/haproxy 파일
	 - rsyslog_haproxy.conf  : haproxy1/haproxy2  시스템에 설치할 /etc/rsyslog.d/haproxy.conf 파일

	 - chk_onos_ins   : haproxy 서비스 상태 확인 스크립트
	 - onos_proxy.json : chk_onos_ins 스크립트에서 참고하는 구성 파일

	 - keepalived-1.2.22.tar.gz : keepalived 패키지 파일
	 - chk_haproxy.sh : keepalived 데몬이 주기적으로 Check 하는 스크립트
	 - vrrp.notify.sh : keepalived 데몬이 VRRP 상태 변경 시 수행하는 스크립트


2. 실행 방법
   - haproxy1, haproxy2와 상호 연동이 가능한 시스템에서 실행한다.
     
     proxyTool 사용법
     
     -h       : show this message
     -i       : set the system to install haproxy, keepalived
                ex) haproxy1, haproxy2, all
     -S       : set the system to get onos proxy stats
                ex) haproxy1, haproxy2, all
     -s       : print haproxy ha status (MASTER/BACKUP)
     -c       : check haproxy and keepalived status
                ex) haproxy1, haproxy2, all
     -p       : print config information (haproxy.json)
     -v       : set verbose log mode (set with '-i' option)
