module Pay
  module Webhooks
    class PaddleController < Pay::ApplicationController
      if Rails.application.config.action_controller.default_protect_from_forgery
        skip_before_action :verify_authenticity_token
      end

      before_action :verify_webhook_signature

      def create
        queue_event(verify_params.as_json)
        head :ok
      rescue Pay::Paddle::Error
        head :bad_request
      end

      private

      def verify_webhook_signature
        _, ts, signature = /ts=(\d+);h1=(\w+)/.match(request.headers["HTTP_PADDLE_SIGNATURE"]).to_a

        expected_signature = OpenSSL::HMAC.hexdigest(
          OpenSSL::Digest.new('sha256'),
          Pay::Paddle.signing_secret,
          "#{ts}:#{request.body.read}"
        )

        if expected_signature != signature
          head :bad_request
        end
      end

      def queue_event(event)
        return unless Pay::Webhooks.delegator.listening?("paddle.#{params[:event_type]}")

        record = Pay::Webhook.create!(processor: :paddle, event_type: params[:event_type], event: event)
        Pay::Webhooks::ProcessJob.perform_later(record)
      end

      def verify_params
        params.except(:action, :controller).permit!
      end
    end
  end
end
