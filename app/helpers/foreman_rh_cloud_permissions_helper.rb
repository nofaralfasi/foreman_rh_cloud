module ForemanRhCloudPermissionsHelper
  # Mapping from Foreman permissions to Insights permissions
  # Based on the permission mapping table:
  #
  # Foreman Permission   | Insights Permissions                              | Paths
  # ---------------------|---------------------------------------------------|----------------------------------
  # view_vulnerability   | inventory:hosts:read                              | GET /api/inventory/v1/hosts(/*)
  # view_vulnerability   | vulnerability:vulnerability_results:read          | GET /api/vulnerability/v1/*
  #                      | vulnerability:system.opt_out:read                 | POST /api/vulnerability/v1/vulnerabilities/cves
  #                      | vulnerability:report_and_export:read              |
  #                      | vulnerability:advanced_report:read                |
  # edit_vulnerability   | vulnerability:system.cve.status:write             | PATCH /api/vulnerability/v1/status
  # edit_vulnerability   | vulnerability:cve.business_risk_and_status:write  | PATCH /api/vulnerability/v1/cves/status
  #                      |                                                   | PATCH /api/vulnerability/v1/cves/business_risk
  # edit_vulnerability   | vulnerability:system.opt_out:write                | PATCH /api/vulnerability/v1/systems/opt_out
  #
  # view_advisor         | advisor:recommendation-results:read               | GET /api/insights/v1/*
  #                      | advisor:exports:read                              |
  # edit_advisor         | advisor:disable-recommendations:write             | POST /api/insights/v1/ack/
  #                      |                                                   | DELETE /api/insights/v1/ack/{rule_id}/
  #                      |                                                   | POST /api/insights/v1/hostack/
  #                      |                                                   | DELETE /api/insights/v1/hostack/{id}/
  #                      |                                                   | POST /api/insights/v1/rule/{rule_id}/unack_hosts/
  #
  PERMISSION_MAPPING = {
    view_vulnerability: [
      'inventory:hosts:read',
      'vulnerability:vulnerability_results:read',
      'vulnerability:system.opt_out:read',
      'vulnerability:report_and_export:read',
      'vulnerability:advanced_report:read',
    ],
    edit_vulnerability: [
      'vulnerability:system.cve.status:write',
      'vulnerability:cve.business_risk_and_status:write',
      'vulnerability:system.opt_out:write',
    ],
    view_advisor: [
      'advisor:recommendation-results:read',
      'advisor:exports:read',
    ],
    edit_advisor: [
      'advisor:disable-recommendations:write',
    ],
  }.freeze

  # Returns user permissions in Chrome API format for Insights applications
  # @return [Array<Hash>] Array of permission objects with :permission and :resourceDefinitions keys
  def insights_user_permissions
    return [] unless User.current

    permissions = []

    PERMISSION_MAPPING.each do |foreman_permission, insights_permissions|
      next unless User.current.can?(foreman_permission)

      insights_permissions.each do |insights_permission|
        permissions << {
          permission: insights_permission,
          resourceDefinitions: [],
        }
      end
    end

    permissions
  end

  # Maps a single Foreman permission to its Insights permissions
  # @param permission [Symbol] Foreman permission symbol
  # @return [Array<String>] Array of Insights permission strings
  def permissions_to_insights_format(permission)
    PERMISSION_MAPPING[permission] || []
  end
end
