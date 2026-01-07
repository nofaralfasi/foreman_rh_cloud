require 'test_plugin_helper'

class ForemanRhCloudPermissionsHelperTest < ActionView::TestCase
  include ForemanRhCloudPermissionsHelper

  setup do
    @user = FactoryBot.create(:user)
    User.current = @user
  end

  teardown do
    User.current = nil
  end

  test 'PERMISSION_MAPPING contains all expected permissions' do
    expected_keys = [:view_vulnerability, :edit_vulnerability, :view_advisor, :edit_advisor]
    assert_equal expected_keys.sort, PERMISSION_MAPPING.keys.sort
  end

  test 'view_vulnerability maps to correct Insights permissions' do
    expected = [
      'inventory:hosts:read',
      'vulnerability:vulnerability_results:read',
      'vulnerability:system.opt_out:read',
      'vulnerability:report_and_export:read',
      'vulnerability:advanced_report:read',
    ]
    assert_equal expected, PERMISSION_MAPPING[:view_vulnerability]
  end

  test 'edit_vulnerability maps to correct Insights permissions' do
    expected = [
      'vulnerability:system.cve.status:write',
      'vulnerability:cve.business_risk_and_status:write',
      'vulnerability:system.opt_out:write',
    ]
    assert_equal expected, PERMISSION_MAPPING[:edit_vulnerability]
  end

  test 'view_advisor maps to correct Insights permissions' do
    expected = [
      'advisor:recommendation-results:read',
      'advisor:exports:read',
    ]
    assert_equal expected, PERMISSION_MAPPING[:view_advisor]
  end

  test 'edit_advisor maps to correct Insights permissions' do
    expected = [
      'advisor:disable-recommendations:write',
    ]
    assert_equal expected, PERMISSION_MAPPING[:edit_advisor]
  end

  test 'insights_user_permissions should return empty array when no user' do
    User.current = nil
    permissions = insights_user_permissions
    assert_empty(permissions)
  end

  test 'insights_user_permissions should return view permissions when user has view_vulnerability' do
    @user.stubs(:can?).with(:view_vulnerability).returns(true)
    @user.stubs(:can?).with(:edit_vulnerability).returns(false)
    @user.stubs(:can?).with(:view_advisor).returns(false)
    @user.stubs(:can?).with(:edit_advisor).returns(false)

    permissions = insights_user_permissions

    assert_equal 5, permissions.length

    permission_strings = permissions.map { |p| p[:permission] }
    assert_includes permission_strings, 'inventory:hosts:read'
    assert_includes permission_strings, 'vulnerability:vulnerability_results:read'
    assert_includes permission_strings, 'vulnerability:system.opt_out:read'
    assert_includes permission_strings, 'vulnerability:report_and_export:read'
    assert_includes permission_strings, 'vulnerability:advanced_report:read'
  end

  test 'insights_user_permissions should return write permissions when user has edit_vulnerability' do
    @user.stubs(:can?).with(:view_vulnerability).returns(false)
    @user.stubs(:can?).with(:edit_vulnerability).returns(true)
    @user.stubs(:can?).with(:view_advisor).returns(false)
    @user.stubs(:can?).with(:edit_advisor).returns(false)

    permissions = insights_user_permissions

    assert_equal 3, permissions.length

    permission_strings = permissions.map { |p| p[:permission] }
    assert_includes permission_strings, 'vulnerability:system.cve.status:write'
    assert_includes permission_strings, 'vulnerability:cve.business_risk_and_status:write'
    assert_includes permission_strings, 'vulnerability:system.opt_out:write'
  end

  test 'insights_user_permissions should return all vulnerability permissions when user has both view and edit' do
    @user.stubs(:can?).with(:view_vulnerability).returns(true)
    @user.stubs(:can?).with(:edit_vulnerability).returns(true)
    @user.stubs(:can?).with(:view_advisor).returns(false)
    @user.stubs(:can?).with(:edit_advisor).returns(false)

    permissions = insights_user_permissions

    assert_equal 8, permissions.length

    permission_strings = permissions.map { |p| p[:permission] }
    # View permissions
    assert_includes permission_strings, 'inventory:hosts:read'
    assert_includes permission_strings, 'vulnerability:vulnerability_results:read'
    # Write permissions
    assert_includes permission_strings, 'vulnerability:system.cve.status:write'
    assert_includes permission_strings, 'vulnerability:cve.business_risk_and_status:write'
  end

  test 'insights_user_permissions should return advisor view permissions when user has view_advisor' do
    @user.stubs(:can?).with(:view_vulnerability).returns(false)
    @user.stubs(:can?).with(:edit_vulnerability).returns(false)
    @user.stubs(:can?).with(:view_advisor).returns(true)
    @user.stubs(:can?).with(:edit_advisor).returns(false)

    permissions = insights_user_permissions

    assert_equal 2, permissions.length

    permission_strings = permissions.map { |p| p[:permission] }
    assert_includes permission_strings, 'advisor:recommendation-results:read'
    assert_includes permission_strings, 'advisor:exports:read'
  end

  test 'insights_user_permissions should return advisor write permissions when user has edit_advisor' do
    @user.stubs(:can?).with(:view_vulnerability).returns(false)
    @user.stubs(:can?).with(:edit_vulnerability).returns(false)
    @user.stubs(:can?).with(:view_advisor).returns(false)
    @user.stubs(:can?).with(:edit_advisor).returns(true)

    permissions = insights_user_permissions

    assert_equal 1, permissions.length

    permission_strings = permissions.map { |p| p[:permission] }
    assert_includes permission_strings, 'advisor:disable-recommendations:write'
  end

  test 'insights_user_permissions should return all permissions when user has all' do
    @user.stubs(:can?).with(:view_vulnerability).returns(true)
    @user.stubs(:can?).with(:edit_vulnerability).returns(true)
    @user.stubs(:can?).with(:view_advisor).returns(true)
    @user.stubs(:can?).with(:edit_advisor).returns(true)

    permissions = insights_user_permissions

    # 5 view_vulnerability + 3 edit_vulnerability + 2 view_advisor + 1 edit_advisor = 11
    assert_equal 11, permissions.length

    permission_strings = permissions.map { |p| p[:permission] }
    # Vulnerability
    assert_includes permission_strings, 'inventory:hosts:read'
    assert_includes permission_strings, 'vulnerability:vulnerability_results:read'
    assert_includes permission_strings, 'vulnerability:system.cve.status:write'
    # Advisor
    assert_includes permission_strings, 'advisor:recommendation-results:read'
    assert_includes permission_strings, 'advisor:exports:read'
    assert_includes permission_strings, 'advisor:disable-recommendations:write'
  end

  test 'insights_user_permissions should have correct Chrome API structure' do
    @user.stubs(:can?).with(:view_vulnerability).returns(true)
    @user.stubs(:can?).with(:edit_vulnerability).returns(false)
    @user.stubs(:can?).with(:view_advisor).returns(false)
    @user.stubs(:can?).with(:edit_advisor).returns(false)

    permissions = insights_user_permissions

    permission = permissions.first
    assert permission.key?(:permission), 'Permission object must have :permission key'
    assert permission.key?(:resourceDefinitions), 'Permission object must have :resourceDefinitions key'
    assert_empty(permission[:resourceDefinitions])
  end

  test 'permissions_to_insights_format should return array of Insights permissions' do
    result = permissions_to_insights_format(:view_vulnerability)
    assert_kind_of Array, result
    assert_equal 5, result.length
    assert_includes result, 'inventory:hosts:read'
  end

  test 'permissions_to_insights_format should return empty array for unknown permission' do
    result = permissions_to_insights_format(:unknown_permission)
    assert_empty(result)
  end
end
