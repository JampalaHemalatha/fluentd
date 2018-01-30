#paths
=begin
pidfile = ' /var/run/td-agent/td-agent.pid'
td-agent_path = '/etc/td-agent'
td-agent.config = '/etc/td-agent/td-agent.config'
fluent.config = '/etc/td-agent/fluent/fluent.config'
plugin = '/etc/td-agent/plugin'
td-agent = '/etc/init.d/td-agent'
=end

FLUENT_CONFIG = '/etc/td-agent/fluent/fluent.conf'
FLUENT_PATH =  '/etc/td-agent/fluent'


title 'fluentd config'

control 'fluentd-01' do
  impact 1.0
  title 'checking operating system properties'
  desc  'checking operating system properties'

#OperationSystem configuration
  describe os[:family] do
      it { should eq 'debian' }
  end
  describe os[:arch] do
      it { should eq 'x86_64' }
  end
  describe os[:name] do
	it { should eq 'ubuntu' }
  end
  describe os[:release] do
 	it { should eq '16.04' }
  end
end

#preinstallation requirements
control 'fluentd-02' do
  impact 1.0
  title 'checking prerequisite packages installed or not'
  desc  'checking prerequisite packages installed or not'

#service ntp should run
describe service('ntp') do      
 	 it { should be_installed}
 	 it { should be_enabled }
      	 it { should be_running }
end
#checking if ntp.conf is a file
describe file('/etc/ntp.conf') do
   it { should be_file }
end
#checking pgrep exit status
describe command('pgrep ntp') do
   its('exit_status') { should eq 0 }
end
#checking ntp_conf driftfile
describe ntp_conf do
  its('driftfile') { should eq '/var/lib/ntp/ntp.drift' }
end
#td-agent service should be installed,enabled and running
describe service('td-agent') do
      it { should be_installed}
      it { should be_enabled }
      it { should be_running }
end
describe package('openssl')do
   it { should be_installed}
end
end



		 
#port
control 'fluentd-03' do
impact 1.0
title 'checking if port is listening or not'
desc 'checking if port is listening or not'

#port 24230 should be enabled 
describe port('24230') do
 it { should be_listening }
 its('processes') { should include 'ruby'}
 its ('protocols') { should include 'tcp' } 
 its('protocols') { should cmp 'tcp' }                                   
end

#port 8888 should be enabled  
port('8888') do
  it { should be_listening}   
  its('processes') { should include 'fluentd'}
  its ('protocols') { should include 'tcp' }
end
end


  
#checking host availability
control 'fluentd-04'do
impact 1.0
title 'checking if host 192.168.0.11 is reachable'
desc 'checking if host is reachable and resolvable'

describe host('192.168.0.11', port: 24230, protocol: 'tcp') do                
      it { should be_reachable }
      it { should be_resolvable }
	its('ipaddress') { should include '192.168.0.11' }
end   
describe host('192.168.0.12', port: 24230, protocol: 'tcp') do                 
      it { should be_reachable }
      it { should be_resolvable }
end
end

#permissions
control "fluentd-05" do
   impact 1.0
   title "Access Permissions"
   desc "Checking file access permissions"

#checking fluent directory access permissions located at /etc/td-agent/fluent
   describe directory('/etc/td-agent/fluent') do                                     
      it { should be_owned_by 'fluent' }
      it { should be_grouped_into 'root' }
      it { should be_readable.by('owner') }
      it { should be_writable.by('owner') }
      it { should be_executable.by('owner') }
      it { should be_readable.by('group') }
      it { should_not be_writable.by('group') }
      it { should_not be_executable.by('group') }
      it { should be_readable.by('others') }
      it { should_not be_writable.by('others') }
      it { should_not be_executable.by('others') }
   end

#checking td-agent.conf file access permissions located at /etc/td-agent/td-agent.conf
   describe file('/etc/td-agent/td-agent.conf') do                             
      it { should be_owned_by 'fluent' }
      it { should be_grouped_into 'root' }
      it { should be_readable.by('owner') }
      it { should be_writable.by('owner') }
      it { should_not be_executable.by('owner') }
      it { should be_readable.by('group') }
      it { should_not be_writable.by('group') }
      it { should_not be_executable.by('group') }
      it { should_not be_readable.by('others') }
      it { should_not be_writable.by('others') }
      it { should_not be_executable.by('others') }
end

#checking plugin  directory access permissions located at /etc/tdagent/plugin
   describe directory('/etc/td-agent/plugin') do                                
      it { should be_owned_by 'fluent' }
      it { should be_readable.by('owner') }
      it { should be_executable.by('owner') }
      it { should_not be_readable.by('others') }
      it { should_not be_writable.by('others') }
      it { should_not be_executable.by('others') } 
end
end

#filecheck
control 'fluentd-06'do
impact 1.0
title 'checking if all the files are exixting'
desc 'checing if required files are available '

#configuration file for configuring
describe file('/etc/td-agent/fluent/fluent.conf')do    
      it { should exist }
      it { should be_file}
end
#configuration file for configuring
describe file('/etc/td-agent/td-agent.conf')do
     it { should exist }
     it { should be_file}
end
#file content
describe file('/etc/td-agent/fluent/fluent.conf') do
its('content') { should include  'host 192.168.0.12'}
its('content') { should include ' bind 127.0.0.1' }
end
end

#security
control 'fluentd-07' do
impact 1.0
title 'secure transaction of data with fluentd'
desc 'secure transaction of data with fluentd'

#add the following lines to your config flie
=begin
<source>
  @type secure_forward
  shared_key YOUR_SHARED_KEY
  self_hostname server.fqdn.local
  cert_auto_generate yes
</source>

<match secure.**>
  @type stdout
</match>
<source>
  @type forward
</source>

<match secure.**>
  @type secure_forward
  shared_key YOUR_SHARED_KEY
  self_hostname "#{Socket.gethostname}"
  <server>
    host RECEIVER_IP
    port 24284
  </server>
</match>
=end
 
describe ssl(port: 24284).protocols('ssl2') do
  it { should be_enabled }
end
end
