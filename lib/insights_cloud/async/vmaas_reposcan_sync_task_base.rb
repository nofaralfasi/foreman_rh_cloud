require 'rest-client'

module InsightsCloud
  module Async
    # Base class for VMaaS reposcan sync functionality
    class VmaasReposcanSyncTaskBase < ::Actions::EntryAction
      include ForemanRhCloud::CertAuth

      def run
        # Trigger VMaaS reposcan sync via IoP gateway
        trigger_vmaas_reposcan_sync
      end

      def rescue_strategy_for_self
        Dynflow::Action::Rescue::Skip
      end

      private

      def trigger_vmaas_reposcan_sync
        # Build the VMaaS reposcan sync URL
        url = InsightsCloud.vmaas_reposcan_sync_url

        response = execute_cloud_request(
          method: :put,
          url: url,
          headers: { 'Content-Type' => 'application/json' }
        )

        logger.info("VMaaS reposcan sync triggered successfully: #{response.code}")
        response
      rescue RestClient::ExceptionWithResponse => e
        logger.error("VMaaS reposcan sync failed: #{e.response&.code} - #{e.response&.body}")
        raise
      rescue StandardError => e
        logger.error("Error triggering VMaaS reposcan sync: #{e.message}")
        raise
      end

      def logger
        action_logger
      end
    end
  end
end
