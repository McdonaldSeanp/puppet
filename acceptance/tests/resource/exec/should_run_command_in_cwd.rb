test_name "The Exec resource should run commands in the specified cwd" do
  tag 'audit:high',
      'audit:acceptance'

  require 'puppet/acceptance/windows_utils'
  extend Puppet::Acceptance::WindowsUtils


  def exec_resource_manifest(command, params = {})
    default_params = {
      :command   => command
    }
    params = default_params.merge(params)

    params_str = params.map do |param, value|
      value_str = value.to_s
      # Single quote the strings in case our value is a Windows
      # path
      value_str = "'#{value_str}'" if value.is_a?(String)

      "  #{param} => #{value_str}"
    end.join(",\n")

    <<-MANIFEST
  exec { 'run_test_command':
  #{params_str}
  }
  MANIFEST
  end

  agents.each do |agent|
    # skip the agent on the master, as we don't need to run the tests on the master too
    next if agent == master

    if agent.platform =~ /windows/
      # Use a lambda to wrap any commands in cmd.exe and quotes for windows hosts
      command = lambda { |cmd| "cmd.exe /c \"" + cmd + "\""}
      path = 'C:\Windows\System32'
      cat = 'cmd.exe /c type'
      non_existant_dir = 'C:\does_not_exist'
    else
      command = lambda { |cmd| cmd}
      path = '/usr/bin:/usr/sbin:/bin:/sbin'
      cat = 'cat'
      non_existant_dir = '/var/does_not_exist'
    end

    tmpdir_origin = agent.tmpdir("mock_origindir")
    create_remote_file(agent, File.join(tmpdir_origin, 'test_origindir.txt'), 'foobar')

    step "Defaults to the current directory if the CWD option is not provided" do
      manifest_path = agent.tmpfile('apply_manifest.pp')
      create_remote_file(agent, manifest_path, exec_resource_manifest("#{cat} test_origindir.txt", {:path => path}))
      on(agent, command["cd #{tmpdir_origin} && puppet apply #{manifest_path} --detailed-exitcodes"], :acceptable_exit_codes => [0, 2])
    end

    tmpdir_seperate = agent.tmpdir("mock_seperatedir")
    create_remote_file(agent, File.join(tmpdir_seperate, 'test_seperatedir.txt'), 'foobar')
    create_remote_file(agent, File.join(tmpdir_seperate, 'test_seperatedir_onlyif.txt'), 'foobar')

    step "Fails the exec run if the command requires a specific directory that puppet is not running from" do
      manifest_path = agent.tmpfile('apply_manifest.pp')
      create_remote_file(agent, manifest_path, exec_resource_manifest("#{cat} test_seperatedir.txt", {:path => path}))
      on(agent, command["cd #{tmpdir_origin} && puppet apply #{manifest_path} --detailed-exitcodes"], :acceptable_exit_codes => [1, 4, 6])
    end

    step "Runs the command in the user specified CWD" do
      apply_manifest_on(agent, exec_resource_manifest("#{cat} test_seperatedir.txt", {cwd: tmpdir_seperate, :path => path}), :catch_errors => true)
    end

    step "Errors if the user specified CWD does not exist" do
      apply_manifest_on(agent, exec_resource_manifest("#{cat} test_seperatedir.txt", {cwd: non_existant_dir, :path => path}), :expect_errors => true)
    end

    username = "pl#{rand(999999).to_i}"

    step "Setup user for 'no access' test" do
      agent.user_present(username)
      if agent.platform =~ /solaris/
        # for some reason applications of 'user_present' on solaris 10 don't manage the homedir correctly, so just
        # force a puppet apply to manage the user
        on agent, puppet_resource('user', username, "ensure=present managehome=true home=/export/home/#{username}")
        # we need to create the user directory ourselves in order for solaris users to successfully login
        on(agent, "mkdir /export/home/#{username} && chown -R #{username} /export/home/#{username}")
      elsif agent.platform =~ /osx/
        # we need to create the user directory ourselves in order for macos users to successfully login
        on(agent, "mkdir /Users/#{username} && chown -R #{username}:80 /Users/#{username}")
      end
    end

    tmpdir_noaccess = agent.tmpdir("mock_noaccess")
    create_remote_file(agent, File.join(tmpdir_noaccess, 'noaccess.txt'), 'foobar')

    step "Setup restricted access directory for 'no access' test" do
      if agent.platform =~ /windows/
        deny_administrator_access_to(agent, tmpdir_noaccess)
        deny_administrator_access_to(agent, File.join(tmpdir_noaccess, 'noaccess.txt'))
      else
        if agent.platform =~ /osx/
          # This is a little nuts, but on MacOS the tmpdir returned from agent.tmpdir is located in
          # a directory that users other than root can't even access, i.e. other users won't have access
          # to either the noaccess dir itself (which we want) _or the tmpdir root it's located in_. This is
          # a problem since it will look to puppet like the noacceess dir doesn't exist at all, and so we
          # can't count on any reliaable failure since we want a return indicating no access, not a missing directory.
          #
          # To get around this for MacOS platforms we simply use the new user's homedir as the 'tmpdir' and
          # put the noaccess dir there.
          on(agent, "mkdir /Users/#{username}/noaccess_test && cp #{tmpdir_noaccess}/noaccess.txt /Users/#{username}/noaccess_test && chmod -R 600 /Users/#{username}/noaccess_test")
          tmpdir_noaccess = "/Users/#{username}/noaccess_test"
        end
        # remove permissions for all other users other than root, which should force puppet to fail when running as another user
        on(agent, "chmod -R 600 #{tmpdir_noaccess}")
      end
    end

    step "Errors if the user does not have access to the specified CWD" do
      manifest_path = agent.tmpfile('apply_manifest.pp')
      create_remote_file(agent, manifest_path, exec_resource_manifest("#{cat} noaccess.txt", {:cwd => tmpdir_noaccess, :path => path}))
      if agent.platform =~ /windows/
        on(agent, command["puppet apply #{manifest_path} --detailed-exitcodes"], :acceptable_exit_codes => [4, 6])
      elsif agent.platform =~ /osx/
        # on MacOS we need to copy the manifest to run to the user's home dir and give the user ownership. otherwise puppet won't run on it.
        on(agent, "cp #{manifest_path} /Users/#{username}/noaccess_manifest.pp && chown #{username}:80 /Users/#{username}/noaccess_manifest.pp")
        on(agent, command["su - #{username} -c \"/opt/puppetlabs/bin/puppet apply /Users/#{username}/noaccess_manifest.pp --detailed-exitcodes\""], :acceptable_exit_codes => [4, 6])
      else
        on(agent, "chown #{username} #{manifest_path}")
        if agent.platform =~ /solaris|aix/
          on(agent, command["su - #{username} -c \"/opt/puppetlabs/bin/puppet apply #{manifest_path} --detailed-exitcodes\""], :acceptable_exit_codes => [4])
        else
          on(agent, command["su #{username} -c \"/opt/puppetlabs/bin/puppet apply #{manifest_path} --detailed-exitcodes\""], :acceptable_exit_codes => [4, 6])
        end
      end
    end

    step "remove test user once testing with it is done" do
      agent.user_absent(username)
    end

    step 'Runs a "check" command (:onlyif or :unless) in the user specified CWD' do
      manifest_path = agent.tmpfile('apply_manifest.pp')
      create_remote_file(agent, manifest_path, exec_resource_manifest("#{cat} test_seperatedir.txt", {cwd: tmpdir_seperate, :path => path, :onlyif => "#{cat} test_seperatedir_onlyif.txt"}))
      # puppet runs will return with exit code '2' when puppet actually executes a change. Since running an exec counts as 'executing a change', you can expect puppet to return '2' when
      # the exec actually executes. This test relies on that API behavior to identify that the exec ran.
      on(agent, command["puppet apply #{manifest_path} --detailed-exitcodes"], :acceptable_exit_codes => [2])
    end

    step 'Does not run the exec if the "check" command (:onlyif or :unless) fails' do
      manifest_path = agent.tmpfile('apply_manifest.pp')
      create_remote_file(agent, manifest_path, exec_resource_manifest("#{cat} test_seperatedir.txt", {cwd: tmpdir_seperate, :path => path, :onlyif => "#{cat} does_not_exist.txt"}))
      # This test relies on the opposite behavior as the preceeding test: since puppet will return '0' when no change is made we can rely on that behavior to identify that the
      # puppet run did not execute the exec (because the :onlyif failed)
      on(agent, command["puppet apply #{manifest_path} --detailed-exitcodes"], :acceptable_exit_codes => [0])
    end
  end
end
