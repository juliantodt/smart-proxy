require 'puppetca/puppetca_main'

module Proxy::PuppetCa
  class Api < ::Sinatra::Base
    helpers ::Proxy::Helpers
    authorize_with_trusted_hosts
    authorize_with_ssl_client

    get "/?" do
      content_type :json
      begin
        Proxy::PuppetCa.list.to_json
      rescue => e
        log_halt 406, "Failed to list certificates: #{e}"
      end
    end

    post "/autosign" do
      content_type :json
      csr = params[:csr]
      begin
        Proxy::PuppetCa.autosign(csr)
      rescue => e
        log_halt 406, "Failed to check autosigning for CSR: #{e}"
      end
    end

    post "/:certname" do
      content_type :json
      certname = params[:certname]
      begin
        Proxy::PuppetCa.sign(certname)
      rescue => e
        log_halt 406, "Failed to sign certificate(s) for #{certname}: #{e}"
      end
    end

    delete "/:certname" do
      begin
        content_type :json
        certname = params[:certname]
        Proxy::PuppetCa.clean(certname)
      rescue Proxy::PuppetCa::NotPresent => e
        log_halt 404, e.to_s
      rescue => e
        log_halt 406, "Failed to remove certificate(s) for #{certname}: #{e}"
      end
    end
  end
end
