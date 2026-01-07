require 'test_plugin_helper'
require 'puma/null_io'

class UIRequestForwarderTest < ActiveSupport::TestCase
  include MockCerts

  setup do
    @forwarder = ::ForemanRhCloud::InsightsApiForwarder.new
    @user = FactoryBot.build(:user)
    @organization = FactoryBot.build(:organization)
    @location = FactoryBot.build(:location)

    setup_certs_expectation do
      @forwarder.stubs(:foreman_certificates)
    end

    ForemanRhCloud.stubs(:cert_base_url).returns('https://cert.cloud.example.com')
  end

  test 'should scope GET requests with proper tags' do
    user_agent = { :foo => :bar }
    params = {}

    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/vulnerability/v1/cves/abc-123/affected_systems',
      'REQUEST_METHOD' => 'GET',
      'HTTP_USER_AGENT' => user_agent,
      'rack.input' => ::Puma::NullIO.new,
      'action_dispatch.request.query_parameters' => params
    )

    ::ForemanRhCloud::TagsAuth.any_instance.expects(:update_tag)
    @forwarder.expects(:execute_cloud_request).with do |actual_params|
      actual = actual_params[:headers][:params]
      assert_equal "U:\"#{@user.login}\"O:\"#{@organization.name}\"L:\"#{@location.name}\"", tag_value(actual.find { |param| param[0] == :tags && tag_name(param[1]) =~ /#{ForemanRhCloud::TagsAuth::TAG_NAME}/ }[1])
      true
    end

    @forwarder.forward_request(req, '/api/vulnerability/v1/cves/abc-123/affected_systems', 'test_controller', @user, @organization, @location)

    # This test asserts the parameters that are sent to the execute_cloud_request method.
    # This is done by setting the expectation before the actual call.
  end

  test 'should not scope GET requests for unknown uris' do
    user_agent = { :foo => :bar }
    params = {}

    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/vulnerability/foo/bar',
      'REQUEST_METHOD' => 'GET',
      'HTTP_USER_AGENT' => user_agent,
      'rack.input' => ::Puma::NullIO.new,
      'action_dispatch.request.query_parameters' => params
    )

    ::ForemanRhCloud::TagsAuth.any_instance.expects(:update_tag).never
    @forwarder.expects(:execute_cloud_request).with do |actual_params|
      actual = actual_params[:headers][:params]
      assert_equal 0, actual.count
      true
    end

    @forwarder.forward_request(req, '/api/vulnerability/foo/bar', 'test_controller', @user, @organization, @location)

    # This test asserts the parameters that are sent to the execute_cloud_request method.
    # This is done by setting the expectation before the actual call.
  end

  test 'should merge URI params in GET requests' do
    user_agent = { :foo => :bar }
    params = { :page => 5, :per_page => 42 }

    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/vulnerability/v1/cves/abc-123/affected_systems',
      'REQUEST_METHOD' => 'GET',
      'HTTP_USER_AGENT' => user_agent,
      'rack.input' => ::Puma::NullIO.new,
      'action_dispatch.request.query_parameters' => params
    )

    ::ForemanRhCloud::TagsAuth.any_instance.expects(:update_tag)
    @forwarder.expects(:execute_cloud_request).with do |actual_params|
      actual = actual_params[:headers][:params]
      assert_equal "U:\"#{@user.login}\"O:\"#{@organization.name}\"L:\"#{@location.name}\"", tag_value(actual.find { |param| param[0] == :tags && tag_name(param[1]) =~ /#{ForemanRhCloud::TagsAuth::TAG_NAME}/ }[1])
      assert_equal 5, actual.find { |param| param[0] == :page }[1]
      assert_equal 42, actual.find { |param| param[0] == :per_page }[1]
      true
    end

    @forwarder.forward_request(req, '/api/vulnerability/v1/cves/abc-123/affected_systems', 'test_controller', @user, @organization, @location)
    # This test asserts the parameters that are sent to the execute_cloud_request method.
    # This is done by setting the expectation before the actual call.
  end

  test 'should not scope POST requests' do
    post_data = 'Random POST data'
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/foo/bar',
      'REQUEST_METHOD' => 'POST',
      'rack.input' => ::Puma::NullIO.new,
      'RAW_POST_DATA' => post_data
    )

    ::ForemanRhCloud::TagsAuth.any_instance.expects(:update_tag).never
    @forwarder.expects(:execute_cloud_request).with do |actual_params|
      actual = actual_params[:headers][:params]
      assert_equal 0, actual.count
      true
    end

    @forwarder.forward_request(req, '/api/vulnerability/v1/cves', 'test_controller', @user, @organization, @location)

    # This test asserts the parameters that are sent to the execute_cloud_request method.
    # This is done by setting the expectation before the actual call.
  end

  test 'should not scope PUT requests' do
    put_data = 'Random PUT data'
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/foo/bar',
      'REQUEST_METHOD' => 'PUT',
      'rack.input' => ::Puma::NullIO.new,
      'RAW_POST_DATA' => put_data
    )

    ::ForemanRhCloud::TagsAuth.any_instance.expects(:update_tag).never
    @forwarder.expects(:execute_cloud_request).with do |actual_params|
      actual = actual_params[:headers][:params]
      assert_equal 0, actual.count
      true
    end

    @forwarder.forward_request(req, '/api/vulnerability/v1/cves', 'test_controller', @user, @organization, @location)

    # This test asserts the parameters that are sent to the execute_cloud_request method.
    # This is done by setting the expectation before the actual call.
  end

  test 'should not scope PATCH requests' do
    post_data = 'Random PATCH data'
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/foo/bar',
      'REQUEST_METHOD' => 'PATCH',
      'rack.input' => ::Puma::NullIO.new,
      'RAW_POST_DATA' => post_data,
      "action_dispatch.request.path_parameters" => { :format => "json" }
    )

    ::ForemanRhCloud::TagsAuth.any_instance.expects(:update_tag).never
    @forwarder.expects(:execute_cloud_request).with do |actual_params|
      actual = actual_params[:headers][:params]
      assert_equal 0, actual.count
      true
    end

    @forwarder.forward_request(req, '/api/vulnerability/v1/cves', 'test_controller', @user, @organization, @location)

    # This test asserts the parameters that are sent to the execute_cloud_request method.
    # This is done by setting the expectation before the actual call.
  end

  test 'scope_request? should return tag_name for scoped requests' do
    get_req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/vulnerability/v1/vulnerabilities/cves',
      'REQUEST_METHOD' => 'GET',
      'rack.input' => ::Puma::NullIO.new
    )

    result = @forwarder.send(:scope_request?, get_req, 'api/vulnerability/v1/vulnerabilities/cves')
    assert_equal :tags, result
  end

  test 'scope_request? should return nil for non-GET requests' do
    post_req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/vulnerability/v1/cves',
      'REQUEST_METHOD' => 'POST',
      'rack.input' => ::Puma::NullIO.new
    )

    result = @forwarder.send(:scope_request?, post_req, '/api/vulnerability/v1/cves')
    assert_nil result
  end

  test 'scope_request? should return nil for unmatched paths' do
    get_req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/unmatched/path',
      'REQUEST_METHOD' => 'GET',
      'rack.input' => ::Puma::NullIO.new
    )

    result = @forwarder.send(:scope_request?, get_req, '/api/unmatched/path')
    assert_nil result
  end

  test 'prepare_tags should use provided tag_name' do
    result = @forwarder.send(:prepare_tags, @user, @organization, @location, :custom_tag)

    assert_equal 1, result.length
    assert_equal :custom_tag, result[0][0]
    assert_equal "U:\"#{@user.login}\"O:\"#{@organization.name}\"L:\"#{@location.name}\"", tag_value(result[0][1])
  end

  def tag_value(param_value)
    return param_value unless param_value.is_a?(String)

    tag_string = CGI.unescape(param_value)
    tag_string.split('=')[1]
  end

  def tag_name(param_value)
    return param_value unless param_value.is_a?(String)

    tag_string = CGI.unescape(param_value)
    tag_string.split('=')[0]
  end

  # Permission enforcement tests

  # GET /api/inventory/v1/hosts requires view_vulnerability
  test 'should allow GET request to inventory hosts when user has view_vulnerability permission' do
    user_agent = { :foo => :bar }
    params = {}

    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/inventory/v1/hosts',
      'REQUEST_METHOD' => 'GET',
      'HTTP_USER_AGENT' => user_agent,
      'rack.input' => ::Puma::NullIO.new,
      'action_dispatch.request.query_parameters' => params
    )

    @user.stubs(:can?).with(:view_vulnerability).returns(true)
    ::ForemanRhCloud::TagsAuth.any_instance.expects(:update_tag)
    @forwarder.expects(:execute_cloud_request).returns(true)

    @forwarder.forward_request(req, 'api/inventory/v1/hosts', 'test_controller', @user, @organization, @location)
  end

  test 'should deny GET request to inventory hosts when user lacks view_vulnerability permission' do
    user_agent = { :foo => :bar }
    params = {}

    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/inventory/v1/hosts',
      'REQUEST_METHOD' => 'GET',
      'HTTP_USER_AGENT' => user_agent,
      'rack.input' => ::Puma::NullIO.new,
      'action_dispatch.request.query_parameters' => params
    )

    @user.stubs(:can?).with(:view_vulnerability).returns(false)

    assert_raises(::Foreman::Exception) do
      @forwarder.forward_request(req, 'api/inventory/v1/hosts', 'test_controller', @user, @organization, @location)
    end
  end

  # POST /api/vulnerability/v1/vulnerabilities/cves requires view_vulnerability
  test 'should allow POST request to vulnerabilities cves when user has view_vulnerability permission' do
    post_data = '{"test": "data"}'
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/vulnerability/v1/vulnerabilities/cves',
      'REQUEST_METHOD' => 'POST',
      'rack.input' => ::Puma::NullIO.new,
      'RAW_POST_DATA' => post_data
    )

    @user.stubs(:can?).with(:view_vulnerability).returns(true)
    @forwarder.expects(:execute_cloud_request).returns(true)

    @forwarder.forward_request(req, 'api/vulnerability/v1/vulnerabilities/cves', 'test_controller', @user, @organization, @location)
  end

  test 'should deny POST request to vulnerabilities cves when user lacks view_vulnerability permission' do
    post_data = '{"test": "data"}'
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/vulnerability/v1/vulnerabilities/cves',
      'REQUEST_METHOD' => 'POST',
      'rack.input' => ::Puma::NullIO.new,
      'RAW_POST_DATA' => post_data
    )

    @user.stubs(:can?).with(:view_vulnerability).returns(false)

    assert_raises(::Foreman::Exception) do
      @forwarder.forward_request(req, 'api/vulnerability/v1/vulnerabilities/cves', 'test_controller', @user, @organization, @location)
    end
  end

  # PATCH /api/vulnerability/v1/status requires edit_vulnerability
  test 'should allow PATCH request to vulnerability status when user has edit_vulnerability permission' do
    patch_data = '{"status": "resolved"}'
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/vulnerability/v1/status',
      'REQUEST_METHOD' => 'PATCH',
      'rack.input' => ::Puma::NullIO.new,
      'RAW_POST_DATA' => patch_data,
      "action_dispatch.request.path_parameters" => { :format => "json" }
    )

    @user.stubs(:can?).with(:edit_vulnerability).returns(true)
    @forwarder.expects(:execute_cloud_request).returns(true)

    @forwarder.forward_request(req, 'api/vulnerability/v1/status', 'test_controller', @user, @organization, @location)
  end

  test 'should deny PATCH request to vulnerability status when user lacks edit_vulnerability permission' do
    patch_data = '{"status": "resolved"}'
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/vulnerability/v1/status',
      'REQUEST_METHOD' => 'PATCH',
      'rack.input' => ::Puma::NullIO.new,
      'RAW_POST_DATA' => patch_data,
      "action_dispatch.request.path_parameters" => { :format => "json" }
    )

    @user.stubs(:can?).with(:edit_vulnerability).returns(false)

    assert_raises(::Foreman::Exception) do
      @forwarder.forward_request(req, 'api/vulnerability/v1/status', 'test_controller', @user, @organization, @location)
    end
  end

  # PATCH /api/vulnerability/v1/cves/business_risk requires edit_vulnerability
  test 'should allow PATCH request to cves business_risk when user has edit_vulnerability permission' do
    patch_data = '{"business_risk": 3}'
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/vulnerability/v1/cves/business_risk',
      'REQUEST_METHOD' => 'PATCH',
      'rack.input' => ::Puma::NullIO.new,
      'RAW_POST_DATA' => patch_data,
      "action_dispatch.request.path_parameters" => { :format => "json" }
    )

    @user.stubs(:can?).with(:edit_vulnerability).returns(true)
    @forwarder.expects(:execute_cloud_request).returns(true)

    @forwarder.forward_request(req, 'api/vulnerability/v1/cves/business_risk', 'test_controller', @user, @organization, @location)
  end

  # PATCH /api/vulnerability/v1/systems/opt_out requires edit_vulnerability
  test 'should allow PATCH request to systems opt_out when user has edit_vulnerability permission' do
    patch_data = '{"opt_out": true}'
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/vulnerability/v1/systems/opt_out',
      'REQUEST_METHOD' => 'PATCH',
      'rack.input' => ::Puma::NullIO.new,
      'RAW_POST_DATA' => patch_data,
      "action_dispatch.request.path_parameters" => { :format => "json" }
    )

    @user.stubs(:can?).with(:edit_vulnerability).returns(true)
    @forwarder.expects(:execute_cloud_request).returns(true)

    @forwarder.forward_request(req, 'api/vulnerability/v1/systems/opt_out', 'test_controller', @user, @organization, @location)
  end

  # Unprotected endpoints (no permission required)
  test 'should allow GET requests to vulnerability dashbar without permission checks' do
    user_agent = { :foo => :bar }
    params = {}

    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/vulnerability/v1/dashbar',
      'REQUEST_METHOD' => 'GET',
      'HTTP_USER_AGENT' => user_agent,
      'rack.input' => ::Puma::NullIO.new,
      'action_dispatch.request.query_parameters' => params
    )

    ::ForemanRhCloud::TagsAuth.any_instance.expects(:update_tag)
    @forwarder.expects(:execute_cloud_request).returns(true)

    @forwarder.forward_request(req, 'api/vulnerability/v1/dashbar', 'test_controller', @user, @organization, @location)
  end

  # Helper method tests
  test 'required_permission_for should return view_vulnerability for inventory hosts GET' do
    permission = @forwarder.send(:required_permission_for, 'api/inventory/v1/hosts', 'GET')
    assert_equal :view_vulnerability, permission
  end

  test 'required_permission_for should return view_vulnerability for vulnerabilities cves POST' do
    permission = @forwarder.send(:required_permission_for, 'api/vulnerability/v1/vulnerabilities/cves', 'POST')
    assert_equal :view_vulnerability, permission
  end

  test 'required_permission_for should return edit_vulnerability for status PATCH' do
    permission = @forwarder.send(:required_permission_for, 'api/vulnerability/v1/status', 'PATCH')
    assert_equal :edit_vulnerability, permission
  end

  test 'required_permission_for should return edit_vulnerability for cves status PATCH' do
    permission = @forwarder.send(:required_permission_for, 'api/vulnerability/v1/cves/status', 'PATCH')
    assert_equal :edit_vulnerability, permission
  end

  test 'required_permission_for should return edit_vulnerability for cves business_risk PATCH' do
    permission = @forwarder.send(:required_permission_for, 'api/vulnerability/v1/cves/business_risk', 'PATCH')
    assert_equal :edit_vulnerability, permission
  end

  test 'required_permission_for should return edit_vulnerability for systems opt_out PATCH' do
    permission = @forwarder.send(:required_permission_for, 'api/vulnerability/v1/systems/opt_out', 'PATCH')
    assert_equal :edit_vulnerability, permission
  end

  test 'required_permission_for should return nil for unprotected endpoint' do
    permission = @forwarder.send(:required_permission_for, 'api/vulnerability/v1/dashbar', 'GET')
    assert_nil permission
  end

  test 'required_permission_for should return nil for unknown endpoint' do
    permission = @forwarder.send(:required_permission_for, 'api/unknown/endpoint', 'GET')
    assert_nil permission
  end

  test 'user_has_permission? should return true when user has permission' do
    @user.stubs(:can?).with(:view_vulnerability).returns(true)
    assert @forwarder.send(:user_has_permission?, @user, :view_vulnerability)
  end

  test 'user_has_permission? should return false when user lacks permission' do
    @user.stubs(:can?).with(:view_vulnerability).returns(false)
    refute @forwarder.send(:user_has_permission?, @user, :view_vulnerability)
  end

  test 'user_has_permission? should return false when user is nil' do
    refute @forwarder.send(:user_has_permission?, nil, :view_vulnerability)
  end

  # Advisor permission tests

  # GET /api/insights/v1/* requires view_advisor
  test 'should allow GET request to insights endpoint when user has view_advisor permission' do
    user_agent = { :foo => :bar }
    params = {}

    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/insights/v1/stats/systems',
      'REQUEST_METHOD' => 'GET',
      'HTTP_USER_AGENT' => user_agent,
      'rack.input' => ::Puma::NullIO.new,
      'action_dispatch.request.query_parameters' => params
    )

    @user.stubs(:can?).with(:view_advisor).returns(true)
    ::ForemanRhCloud::TagsAuth.any_instance.expects(:update_tag)
    @forwarder.expects(:execute_cloud_request).returns(true)

    @forwarder.forward_request(req, 'api/insights/v1/stats/systems', 'test_controller', @user, @organization, @location)
  end

  test 'should deny GET request to insights endpoint when user lacks view_advisor permission' do
    user_agent = { :foo => :bar }
    params = {}

    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/insights/v1/stats/systems',
      'REQUEST_METHOD' => 'GET',
      'HTTP_USER_AGENT' => user_agent,
      'rack.input' => ::Puma::NullIO.new,
      'action_dispatch.request.query_parameters' => params
    )

    @user.stubs(:can?).with(:view_advisor).returns(false)

    assert_raises(::Foreman::Exception) do
      @forwarder.forward_request(req, 'api/insights/v1/stats/systems', 'test_controller', @user, @organization, @location)
    end
  end

  # POST /api/insights/v1/ack/ requires edit_advisor
  test 'should allow POST request to insights ack when user has edit_advisor permission' do
    post_data = '{"rule_id": "test|RULE"}'
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/insights/v1/ack/',
      'REQUEST_METHOD' => 'POST',
      'rack.input' => ::Puma::NullIO.new,
      'RAW_POST_DATA' => post_data
    )

    @user.stubs(:can?).with(:edit_advisor).returns(true)
    @forwarder.expects(:execute_cloud_request).returns(true)

    @forwarder.forward_request(req, 'api/insights/v1/ack/', 'test_controller', @user, @organization, @location)
  end

  test 'should deny POST request to insights ack when user lacks edit_advisor permission' do
    post_data = '{"rule_id": "test|RULE"}'
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/insights/v1/ack/',
      'REQUEST_METHOD' => 'POST',
      'rack.input' => ::Puma::NullIO.new,
      'RAW_POST_DATA' => post_data
    )

    @user.stubs(:can?).with(:edit_advisor).returns(false)

    assert_raises(::Foreman::Exception) do
      @forwarder.forward_request(req, 'api/insights/v1/ack/', 'test_controller', @user, @organization, @location)
    end
  end

  # DELETE /api/insights/v1/ack/{rule_id}/ requires edit_advisor
  test 'should allow DELETE request to insights ack rule when user has edit_advisor permission' do
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/insights/v1/ack/test_rule_id',
      'REQUEST_METHOD' => 'DELETE',
      'rack.input' => ::Puma::NullIO.new
    )

    @user.stubs(:can?).with(:edit_advisor).returns(true)
    @forwarder.expects(:execute_cloud_request).returns(true)

    @forwarder.forward_request(req, 'api/insights/v1/ack/test_rule_id', 'test_controller', @user, @organization, @location)
  end

  test 'should deny DELETE request to insights ack rule when user lacks edit_advisor permission' do
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/insights/v1/ack/test_rule_id',
      'REQUEST_METHOD' => 'DELETE',
      'rack.input' => ::Puma::NullIO.new
    )

    @user.stubs(:can?).with(:edit_advisor).returns(false)

    assert_raises(::Foreman::Exception) do
      @forwarder.forward_request(req, 'api/insights/v1/ack/test_rule_id', 'test_controller', @user, @organization, @location)
    end
  end

  # POST /api/insights/v1/hostack/ requires edit_advisor
  test 'should allow POST request to insights hostack when user has edit_advisor permission' do
    post_data = '{"host_id": "test-uuid", "rule_id": "test|RULE"}'
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/insights/v1/hostack/',
      'REQUEST_METHOD' => 'POST',
      'rack.input' => ::Puma::NullIO.new,
      'RAW_POST_DATA' => post_data
    )

    @user.stubs(:can?).with(:edit_advisor).returns(true)
    @forwarder.expects(:execute_cloud_request).returns(true)

    @forwarder.forward_request(req, 'api/insights/v1/hostack/', 'test_controller', @user, @organization, @location)
  end

  test 'should deny POST request to insights hostack when user lacks edit_advisor permission' do
    post_data = '{"host_id": "test-uuid", "rule_id": "test|RULE"}'
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/insights/v1/hostack/',
      'REQUEST_METHOD' => 'POST',
      'rack.input' => ::Puma::NullIO.new,
      'RAW_POST_DATA' => post_data
    )

    @user.stubs(:can?).with(:edit_advisor).returns(false)

    assert_raises(::Foreman::Exception) do
      @forwarder.forward_request(req, 'api/insights/v1/hostack/', 'test_controller', @user, @organization, @location)
    end
  end

  # DELETE /api/insights/v1/hostack/{id}/ requires edit_advisor
  test 'should allow DELETE request to insights hostack id when user has edit_advisor permission' do
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/insights/v1/hostack/12345',
      'REQUEST_METHOD' => 'DELETE',
      'rack.input' => ::Puma::NullIO.new
    )

    @user.stubs(:can?).with(:edit_advisor).returns(true)
    @forwarder.expects(:execute_cloud_request).returns(true)

    @forwarder.forward_request(req, 'api/insights/v1/hostack/12345', 'test_controller', @user, @organization, @location)
  end

  test 'should deny DELETE request to insights hostack id when user lacks edit_advisor permission' do
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/insights/v1/hostack/12345',
      'REQUEST_METHOD' => 'DELETE',
      'rack.input' => ::Puma::NullIO.new
    )

    @user.stubs(:can?).with(:edit_advisor).returns(false)

    assert_raises(::Foreman::Exception) do
      @forwarder.forward_request(req, 'api/insights/v1/hostack/12345', 'test_controller', @user, @organization, @location)
    end
  end

  # POST /api/insights/v1/rule/{rule_id}/unack_hosts/ requires edit_advisor
  test 'should allow POST request to rule unack_hosts when user has edit_advisor permission' do
    post_data = '{"host_ids": ["uuid1", "uuid2"]}'
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/insights/v1/rule/test_rule/unack_hosts',
      'REQUEST_METHOD' => 'POST',
      'rack.input' => ::Puma::NullIO.new,
      'RAW_POST_DATA' => post_data
    )

    @user.stubs(:can?).with(:edit_advisor).returns(true)
    @forwarder.expects(:execute_cloud_request).returns(true)

    @forwarder.forward_request(req, 'api/insights/v1/rule/test_rule/unack_hosts', 'test_controller', @user, @organization, @location)
  end

  test 'should deny POST request to rule unack_hosts when user lacks edit_advisor permission' do
    post_data = '{"host_ids": ["uuid1", "uuid2"]}'
    req = ActionDispatch::Request.new(
      'REQUEST_URI' => '/api/insights/v1/rule/test_rule/unack_hosts',
      'REQUEST_METHOD' => 'POST',
      'rack.input' => ::Puma::NullIO.new,
      'RAW_POST_DATA' => post_data
    )

    @user.stubs(:can?).with(:edit_advisor).returns(false)

    assert_raises(::Foreman::Exception) do
      @forwarder.forward_request(req, 'api/insights/v1/rule/test_rule/unack_hosts', 'test_controller', @user, @organization, @location)
    end
  end

  # Helper method tests for advisor
  test 'required_permission_for should return view_advisor for insights GET' do
    permission = @forwarder.send(:required_permission_for, 'api/insights/v1/stats/systems', 'GET')
    assert_equal :view_advisor, permission
  end

  test 'required_permission_for should return edit_advisor for ack POST' do
    permission = @forwarder.send(:required_permission_for, 'api/insights/v1/ack/', 'POST')
    assert_equal :edit_advisor, permission
  end

  test 'required_permission_for should return edit_advisor for ack DELETE' do
    permission = @forwarder.send(:required_permission_for, 'api/insights/v1/ack/rule_id', 'DELETE')
    assert_equal :edit_advisor, permission
  end

  test 'required_permission_for should return edit_advisor for hostack POST' do
    permission = @forwarder.send(:required_permission_for, 'api/insights/v1/hostack/', 'POST')
    assert_equal :edit_advisor, permission
  end

  test 'required_permission_for should return edit_advisor for hostack DELETE' do
    permission = @forwarder.send(:required_permission_for, 'api/insights/v1/hostack/123', 'DELETE')
    assert_equal :edit_advisor, permission
  end

  test 'required_permission_for should return edit_advisor for rule unack_hosts POST' do
    permission = @forwarder.send(:required_permission_for, 'api/insights/v1/rule/test_rule/unack_hosts', 'POST')
    assert_equal :edit_advisor, permission
  end
end
