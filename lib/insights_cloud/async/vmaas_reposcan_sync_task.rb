require_relative 'vmaas_reposcan_sync_task_base'

module InsightsCloud
  module Async
    # Triggers VMaaS reposcan sync when repositories are synced
    class VmaasReposcanSyncTask < VmaasReposcanSyncTaskBase
      def plan(repo, *_args)
        return unless repo.is_a?(::Katello::Repository) && ForemanRhCloud.with_iop_smart_proxy?

        plan_self
      end

      def self.subscribe
        return unless defined?(::Katello)

        'Actions::Katello::Repository::Sync'.constantize
      rescue NameError
        Rails.logger.debug("VMaaS reposcan sync: Repository::Sync action not found")
        nil
      end
    end
  end
end
